/**
 * Cross-process inference lock.
 *
 * The in-process promise-chain semaphore in index.ts only serialises calls
 * within a single houtini-lm process. Under the multi-agent deployment (several
 * MCP client connections, each its own process) they all hit one loaded model
 * in parallel, stacking prefill/timeout. This advisory file lock serialises
 * inference across processes on the same machine.
 *
 * Design:
 * - Atomic exclusive create (`wx`) of the lock file is the acquire primitive.
 * - Each acquisition writes a UNIQUE token. Every destructive op (release, steal,
 *   exit cleanup) first re-reads the file and only unlinks when the on-disk token
 *   still matches, so a process can NEVER delete a lock it doesn't own — which is
 *   what previously let a steal race cascade into extra concurrent holders.
 * - Staleness is AGE-FIRST (past the threshold → steal regardless), then same-host
 *   dead-PID (`kill(pid,0)` → ESRCH → steal). Age-first means a reused PID can't
 *   pin a dead holder's lock forever.
 * - A read failure is classified, not collapsed to "no lock". A GARBLED file (empty or
 *   non-JSON, e.g. a holder died between create and write) carries no token, so
 *   token-checked removal can never clear it and it is removed outright. A file we simply
 *   cannot READ (EACCES/EBUSY/EIO) is not evidence of a dead holder and never authorises
 *   a steal.
 * - FAIL-OPEN: any fs error, or waiting past the cap, proceeds WITHOUT the lock
 *   rather than hanging a tool call. Serialisation is a throughput optimisation,
 *   never a correctness dependency. The deadline is enforced on the steal path too —
 *   every path out of the acquire loop is bounded.
 *
 * Residual: if a holder is hard-killed and several waiters race to steal in the
 * same sub-millisecond window, a transient double-acquire is possible (two
 * inferences run in parallel briefly, i.e. the un-optimised behaviour). It is
 * self-healing and, thanks to token-checked release, never cascades. Acceptable
 * for a best-effort optimisation.
 */

import { openSync, writeSync, closeSync, readFileSync, unlinkSync, mkdirSync } from 'node:fs';
import { join } from 'node:path';
import { homedir, hostname } from 'node:os';
import { randomUUID } from 'node:crypto';

const LOCK_DIR = join(homedir(), '.houtini-lm');
const LOCK_PATH = join(LOCK_DIR, 'inference.lock');
const HOST = hostname();

const ENABLED = process.env.HOUTINI_LM_CROSS_PROCESS_LOCK !== '0';
const POLL_MS = 150;
// Stale-by-time threshold must exceed the inference soft-timeout (5 min) so we
// never steal a lock from a genuinely long-running inference on time alone.
const STALE_MS = 7 * 60_000;
// Default cap on how long we'll wait before giving up and proceeding unlocked.
//
// This is DELIBERATELY below STALE_MS, and that is not a bug. shouldSteal() ages out a
// lock on `Date.now() - info.at`, i.e. the age of the LOCK, not how long the current
// caller has waited — so a caller arriving at an already-stale lock steals it on its
// first iteration and never consults this cap. Raising it above STALE_MS would only make
// callers block longer before failing open, which is the wrong direction for a module
// whose contract is that serialisation is never a correctness dependency.
const DEFAULT_MAX_WAIT_MS = 6 * 60_000;

interface LockInfo { pid?: number; host?: string; at?: number; token?: string }

const sleep = (ms: number) => new Promise<void>((r) => setTimeout(r, ms));

// The token of the lock this process currently holds (null when not holding).
// Every unlink is gated on the on-disk token still equalling this, so we only
// ever delete our own lock.
let myToken: string | null = null;

process.on('exit', () => {
  if (myToken && readLock()?.token === myToken) {
    try { unlinkSync(LOCK_PATH); } catch { /* ignore */ }
  }
});

/**
 * Reading the lock has three distinct failure modes and they need different handling.
 * Collapsing them all to `null` is what allowed a garbled file to wedge the acquire loop:
 *
 * - `missing`    — no file. Just retry the acquire.
 * - `garbled`    — file exists but is empty or not JSON. There is NO token to match, so
 *                  token-checked removal is a no-op and the file must be removed outright
 *                  or nothing will ever clear it. Reachable whenever a holder dies between
 *                  creating the file and writing to it.
 * - `unreadable` — the file exists but we could not read it (EACCES, EBUSY, EIO). This is
 *                  NOT evidence the lock is dead, so it must never authorise a steal.
 */
type LockRead =
  | { state: 'ok'; info: LockInfo }
  | { state: 'missing' }
  | { state: 'garbled' }
  | { state: 'unreadable' };

function readLockDetailed(): LockRead {
  let raw: string;
  try {
    raw = readFileSync(LOCK_PATH, 'utf8');
  } catch (e) {
    return (e as NodeJS.ErrnoException).code === 'ENOENT'
      ? { state: 'missing' }
      : { state: 'unreadable' };
  }
  try {
    const info = JSON.parse(raw) as LockInfo;
    // A JSON scalar (`null`, `7`, `"x"`) parses fine but is not a lock record.
    if (!info || typeof info !== 'object') return { state: 'garbled' };
    return { state: 'ok', info };
  } catch {
    return { state: 'garbled' };
  }
}

/** Convenience wrapper for the read-only callers that only care about a valid record. */
function readLock(): LockInfo | null {
  const r = readLockDetailed();
  return r.state === 'ok' ? r.info : null;
}

/** Should the given on-disk lock be stolen? Age first (covers PID reuse and
 *  wedged holders), then same-host dead-PID. */
function shouldSteal(info: LockInfo | null): boolean {
  if (!info) return true; // unreadable/garbled → stealable
  if (typeof info.at === 'number' && Date.now() - info.at > STALE_MS) return true;
  if (info.host === HOST && typeof info.pid === 'number') {
    try { process.kill(info.pid, 0); } // probe existence; no signal sent
    catch (e) { if ((e as NodeJS.ErrnoException).code === 'ESRCH') return true; }
    // EPERM (exists, not ours to signal) → alive → not stale
  }
  return false;
}

/** Remove the lock only if it STILL holds the exact token we deemed stale, so we
 *  don't clobber a fresh lock another waiter created in the meantime. */
function stealIfUnchanged(expectedToken: string | undefined): void {
  const cur = readLock();
  if (cur && cur.token === expectedToken) {
    try { unlinkSync(LOCK_PATH); } catch { /* another waiter beat us to it */ }
  }
}

/**
 * Remove a lock file that carries no usable token. Unconditional by necessity: there is
 * nothing to compare against, so `stealIfUnchanged` can never remove it. Without this the
 * acquire loop retries forever against a file it will not delete.
 *
 * The unconditional unlink is safe precisely because it is gated on `garbled` rather than
 * on any read failure — a lock we merely cannot read is left alone.
 */
function removeGarbledLock(): void {
  try { unlinkSync(LOCK_PATH); } catch { /* another waiter beat us to it */ }
}

/**
 * Acquire the cross-process inference lock. Returns a release function (safe to
 * call more than once; only unlinks if we still own the file). `onWait` is
 * invoked periodically while blocked so the caller can emit keepalive progress.
 * `maxWaitMs` caps the wait before failing open — pass a value under the client
 * request timeout when the caller cannot emit keepalives.
 */
export async function acquireInferenceLock(
  opts: { onWait?: (waitedMs: number) => void; maxWaitMs?: number } = {},
): Promise<() => void> {
  if (!ENABLED) return () => { /* disabled */ };
  const { onWait, maxWaitMs = DEFAULT_MAX_WAIT_MS } = opts;

  try { mkdirSync(LOCK_DIR, { recursive: true }); } catch { /* ignore */ }

  const start = Date.now();
  let lastTick = 0;
  for (;;) {
    try {
      const token = `${process.pid}-${HOST}-${randomUUID()}`;
      const fd = openSync(LOCK_PATH, 'wx'); // atomic: EEXIST if already held
      // Once the file exists we own the cleanup obligation. A throw from writeSync would
      // otherwise leak the descriptor AND strand a zero-byte lock that no release and no
      // exit handler can remove (myToken is not yet set) — which is exactly the garbled
      // file that used to wedge every other process's acquire loop.
      try {
        writeSync(fd, JSON.stringify({ pid: process.pid, host: HOST, at: Date.now(), token }));
      } catch (writeErr) {
        try { closeSync(fd); } catch { /* ignore */ }
        try { unlinkSync(LOCK_PATH); } catch { /* ignore */ }
        throw writeErr;
      }
      closeSync(fd);
      myToken = token;
      let released = false;
      return () => {
        if (released) return;
        released = true;
        // Only unlink if the file still carries OUR token — never delete a lock
        // that was stolen from us and re-created by someone else.
        if (readLock()?.token === token) {
          try { unlinkSync(LOCK_PATH); } catch { /* ignore */ }
        }
        if (myToken === token) myToken = null;
      };
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code !== 'EEXIST') {
        return () => { /* fail open — run unlocked rather than block */ };
      }
      const read = readLockDetailed();
      // An unreadable file is not evidence of a dead holder, so it must not authorise a
      // steal. Treat it as held and fall through to the wait/fail-open path.
      const stealable =
        read.state === 'garbled' ||
        read.state === 'missing' ||
        (read.state === 'ok' && shouldSteal(read.info));

      if (stealable) {
        if (read.state === 'garbled') removeGarbledLock();
        else if (read.state === 'ok') stealIfUnchanged(read.info.token);
        // Bound the steal path too. It previously `continue`d straight past both the
        // deadline check and the sleep, so any condition that kept re-presenting a
        // stealable lock span a core forever and never failed open.
        if (Date.now() - start > maxWaitMs) {
          return () => { /* gave up during steal contention; run unlocked */ };
        }
        continue; // retry acquire immediately
      }
      const waited = Date.now() - start;
      if (waited > maxWaitMs) return () => { /* gave up waiting; run unlocked */ };
      if (onWait && waited - lastTick >= 2000) { lastTick = waited; onWait(waited); }
      await sleep(POLL_MS);
    }
  }
}
