// Unit test for the context-overflow parser (the self-heal that retries once
// when a proxy advertises a larger context than the model actually loaded).
// Pure function, no backend needed. Run: npm run test:overflow
import { parseContextOverflow, correctedMaxTokens } from './dist/context-overflow.js';

let failed = 0;
const eq = (name, got, want) => {
  const ok = got === want;
  process.stdout.write(`${ok ? 'PASS' : 'FAIL'}  ${name} → ${JSON.stringify(got)}${ok ? '' : ` (want ${JSON.stringify(want)})`}\n`);
  if (!ok) failed++;
};

// --- parseContextOverflow: real backend error shapes ---
eq('vLLM max_model_len chain',
  parseContextOverflow('max_completion_tokens=99002 cannot be greater than max_model_len=max_total_tokens=65536. Please request fewer output tokens.'),
  65536);
eq('OpenAI maximum context length',
  parseContextOverflow("This model's maximum context length is 8192 tokens, however you requested 9000."),
  8192);
eq('llama.cpp n_ctx',
  parseContextOverflow('the request exceeds the available context size. try increasing the context size. n_ctx = 4096'),
  4096);
eq('generic context window',
  parseContextOverflow('context window of 32768 tokens exceeded'),
  32768);

// --- non-overflow errors must NOT match (so we surface the real error, not retry) ---
eq('unrelated 400 → null', parseContextOverflow('The model `coder-next` does not exist.'), null);
eq('empty → null', parseContextOverflow(''), null);
eq('auth error → null', parseContextOverflow('invalid api key'), null);

// --- correctedMaxTokens: leaves room for the prompt, stays inside the window ---
const c = correctedMaxTokens(65536, 90 /*chars*/, 2 /*messages*/);
eq('corrected < real limit', c < 65536, true);
eq('corrected > 0', c > 0, true);
eq('corrected honours floor on a tiny window', correctedMaxTokens(100, 999999, 5), 256);

process.stdout.write(failed ? `\n${failed} FAILED\n` : '\nAll context-overflow tests passed\n');
process.exitCode = failed ? 1 : 0;
