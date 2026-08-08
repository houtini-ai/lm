#!/usr/bin/env node
/**
 * vLLM thinking-model regression test.
 *
 * Guards the fix for: vLLM's OpenAI server only honours enable_thinking when it
 * is nested inside chat_template_kwargs. A top-level enable_thinking (which LM
 * Studio / Ollama accept) is silently dropped, so vLLM thinking models return
 * the answer in reasoning_content with EMPTY content — breaking delegation.
 *
 * Contract asserted against a live vLLM serving a thinking model (Qwen3.6 /
 * Qwen3-Coder-Next): a request with chat_template_kwargs.enable_thinking=false
 * MUST return non-empty content.
 *
 * Skips cleanly (exit 0) when no vLLM / no thinking model is reachable, so CI
 * without a GPU box does not fail.
 *
 * Run: node test-vllm-thinking.mjs   (optional: VLLM_URL, default 127.0.0.1:8000)
 */
const BASE = (process.env.VLLM_URL || 'http://127.0.0.1:8000').replace(/\/$/, '');
const TIMEOUT = 60_000;

async function post(path, body) {
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), TIMEOUT);
  try {
    const r = await fetch(`${BASE}${path}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
      signal: ctrl.signal,
    });
    return r.ok ? await r.json() : null;
  } catch { return null; }
  finally { clearTimeout(t); }
}

async function getModel() {
  try {
    const ctrl = new AbortController();
    const t = setTimeout(() => ctrl.abort(), 5000);
    const r = await fetch(`${BASE}/v1/models`, { signal: ctrl.signal });
    clearTimeout(t);
    if (!r.ok) return null;
    const j = await r.json();
    return j?.data?.[0]?.id ?? null;
  } catch { return null; }
}

// Set exitCode and unwind via a sentinel — never call process.exit() directly,
// which races with undici keepalive sockets and trips a libuv assert on Windows.
class Done { constructor(code, msg, err = false) { this.code = code; this.msg = msg; this.err = err; } }
const skip = (msg) => { throw new Done(0, `SKIP: ${msg}`); };
const fail = (msg) => { throw new Done(1, `FAIL: ${msg}`, true); };
const pass = (msg) => { throw new Done(0, `PASS: ${msg}`); };

async function run() {
const model = await getModel();
if (!model) skip(`no vLLM reachable at ${BASE}`);

const ask = { model, messages: [{ role: 'user', content: 'Reply with exactly the single word: ready' }], max_tokens: 2000 };

// Probe: is this a thinking model that hides content without the toggle?
const plain = await post('/v1/chat/completions', ask);
if (!plain) skip(`vLLM at ${BASE} did not answer a completion`);
const plainContent = (plain.choices?.[0]?.message?.content ?? '').trim();
const plainReasoning = (plain.choices?.[0]?.message?.reasoning ?? plain.choices?.[0]?.message?.reasoning_content ?? '').toString().trim();

if (plainContent.length > 0) {
  skip(`model '${model}' returns content without the toggle (not a thinking model, or thinking already off) — fix not exercised`);
}
if (plainReasoning.length === 0) skip(`model '${model}' returned neither content nor reasoning — cannot characterise`);

// The fix: nested chat_template_kwargs.enable_thinking=false must yield content.
const fixed = await post('/v1/chat/completions', { ...ask, chat_template_kwargs: { enable_thinking: false } });
if (!fixed) fail('request with chat_template_kwargs failed outright');
const fixedContent = (fixed.choices?.[0]?.message?.content ?? '').trim();

if (fixedContent.length > 0) {
  pass(`'${model}': content empty without toggle, populated ('${fixedContent.slice(0, 40)}') with chat_template_kwargs.enable_thinking=false — nesting contract holds`);
} else {
  fail(`'${model}': chat_template_kwargs.enable_thinking=false still returned empty content — vLLM contract changed or model ignores the toggle`);
}
}

run().then(
  () => { console.error('unexpected: run() returned without a verdict'); process.exitCode = 1; },
  (d) => {
    if (d instanceof Done) { (d.err ? console.error : console.log)(d.msg); process.exitCode = d.code; }
    else { console.error(`ERROR: ${d?.stack || d}`); process.exitCode = 1; }
  },
);
