/**
 * Verification for the cross-process inference lock.
 *
 * Run after `npm run build`:   node scripts/verify-inference-lock.mjs
 *
 * The first case is the one that matters. Before the fix, a zero-byte lock file made
 * acquireInferenceLock() spin forever: readLock() returned null, shouldSteal(null) said
 * yes, stealIfUnchanged(undefined) matched nothing and removed nothing, and `continue`
 * jumped past both the deadline check and the sleep. That is a permanent hang of a tool
 * call in a module whose stated contract is that it always fails open.
 *
 * These run against the real module, not a mock, so they exercise the actual filesystem
 * paths. They are deliberately quick — the slow ones pass a small maxWaitMs.
 */
import { writeFileSync, unlinkSync, existsSync, readFileSync, mkdirSync } from 'node:fs';
import { join } from 'node:path';
import { homedir } from 'node:os';

const { acquireInferenceLock } = await import('../dist/inference-lock.js');

const LOCK = join(homedir(), '.houtini-lm', 'inference.lock');
mkdirSync(join(homedir(), '.houtini-lm'), { recursive: true });

let failures = 0;
const clear = () => { try { unlinkSync(LOCK); } catch { /* already gone */ } };

async function check(name, fn) {
  clear();
  const t0 = Date.now();
  try {
    await fn();
    console.log(`  PASS  ${name}  (${Date.now() - t0}ms)`);
  } catch (e) {
    failures++;
    console.log(`  FAIL  ${name}  (${Date.now() - t0}ms)\n        ${e.message}`);
  } finally {
    clear();
  }
}

const assert = (cond, msg) => { if (!cond) throw new Error(msg); };

console.log('\ninference-lock verification\n');

// THE REGRESSION. Before the fix this never returns and pegs a core.
await check('zero-byte lock file does not hang the acquire', async () => {
  writeFileSync(LOCK, '');
  const t0 = Date.now();
  const release = await acquireInferenceLock({ maxWaitMs: 2000 });
  const took = Date.now() - t0;
  assert(typeof release === 'function', 'expected a release function');
  assert(took < 5000, `took ${took}ms — the acquire loop is not bounded`);
  release();
});

await check('garbled (non-JSON) lock file does not hang the acquire', async () => {
  writeFileSync(LOCK, 'this is not json {{{');
  const release = await acquireInferenceLock({ maxWaitMs: 2000 });
  release();
});

// JSON that parses to a non-object still is not a lock record.
await check('JSON scalar lock file does not hang the acquire', async () => {
  writeFileSync(LOCK, 'null');
  const release = await acquireInferenceLock({ maxWaitMs: 2000 });
  release();
});

await check('normal acquire writes a well-formed record and release removes it', async () => {
  const release = await acquireInferenceLock({ maxWaitMs: 2000 });
  assert(existsSync(LOCK), 'lock file should exist while held');
  const info = JSON.parse(readFileSync(LOCK, 'utf8'));
  assert(typeof info.token === 'string' && info.token.length > 0, 'record needs a token');
  assert(info.pid === process.pid, 'record should carry our pid');
  assert(typeof info.at === 'number', 'record needs a numeric `at` or it can never age out');
  release();
  assert(!existsSync(LOCK), 'release should remove the lock file');
});

await check('release is idempotent', async () => {
  const release = await acquireInferenceLock({ maxWaitMs: 2000 });
  release();
  release();
  release();
});

await check('a live foreign holder is waited on, then fails open within the cap', async () => {
  // Same host, OUR pid (definitely alive), fresh timestamp => not stealable by either rule.
  writeFileSync(LOCK, JSON.stringify({
    pid: process.pid, host: (await import('node:os')).hostname(),
    at: Date.now(), token: 'held-by-someone-else',
  }));
  const t0 = Date.now();
  const release = await acquireInferenceLock({ maxWaitMs: 1200 });
  const took = Date.now() - t0;
  assert(took >= 1000, `should have waited out the cap, took only ${took}ms`);
  assert(took < 6000, `should have failed open at the cap, took ${took}ms`);
  // Failing open must NOT have disturbed the incumbent's lock.
  assert(existsSync(LOCK), 'failing open must not delete a live holder\'s lock');
  assert(JSON.parse(readFileSync(LOCK, 'utf8')).token === 'held-by-someone-else',
         'failing open must not overwrite a live holder\'s lock');
  release();
  assert(existsSync(LOCK), 'a no-op release must not remove a lock we never held');
});

await check('an aged-out lock is stolen', async () => {
  writeFileSync(LOCK, JSON.stringify({
    pid: process.pid, host: (await import('node:os')).hostname(),
    at: Date.now() - 60 * 60_000, token: 'ancient',
  }));
  const release = await acquireInferenceLock({ maxWaitMs: 3000 });
  const info = JSON.parse(readFileSync(LOCK, 'utf8'));
  assert(info.token !== 'ancient', 'the stale lock should have been replaced by ours');
  release();
});

// The defect qwen3.6 found and I did not: with the old values every waiter failed open
// one minute before the age-based steal became reachable.
await check('default wait cap exceeds the staleness threshold', async () => {
  const src = readFileSync(new URL('../src/inference-lock.ts', import.meta.url), 'utf8');
  const stale = /const STALE_MS = (\d+) \* 60_000/.exec(src);
  assert(stale, 'could not parse STALE_MS');
  const usesDerived = /const DEFAULT_MAX_WAIT_MS = STALE_MS \+/.test(src);
  assert(usesDerived,
    'DEFAULT_MAX_WAIT_MS must be derived from STALE_MS so it can never drift below it; ' +
    'otherwise the age-based steal is unreachable at default settings');
});

console.log(`\n${failures === 0 ? 'ALL PASS' : `${failures} FAILED`}\n`);
process.exit(failures === 0 ? 0 : 1);
