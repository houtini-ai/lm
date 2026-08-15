// Unit test for HOUTINI_LM_THINKING resolution. Pure function, no backend
// needed. Run after building: npm run test:thinking-mode
import { resolveThinkingOverride } from '../dist/thinking-mode.js';

let failed = 0;
const eq = (name, got, want) => {
  const ok = got === want;
  process.stdout.write(`${ok ? 'PASS' : 'FAIL'}  ${name} → ${JSON.stringify(got)}${ok ? '' : ` (want ${JSON.stringify(want)})`}\n`);
  if (!ok) failed++;
};

eq('on forces thinking for a detected model', resolveThinkingOverride('on', true), true);
eq('on forces thinking for an aliased model', resolveThinkingOverride('on', false), true);
eq('off suppresses thinking for a detected model', resolveThinkingOverride('off', true), false);
eq('off suppresses thinking for an aliased model', resolveThinkingOverride('off', false), false);
eq('auto suppresses a detected thinking model', resolveThinkingOverride('auto', true), false);
eq('auto leaves an unknown model unchanged', resolveThinkingOverride('auto', false), undefined);
eq('unset uses auto detection', resolveThinkingOverride(undefined, true), false);
eq('unknown value uses auto detection', resolveThinkingOverride('unexpected', false), undefined);

process.stdout.write(failed ? `\n${failed} FAILED\n` : '\nAll thinking-mode tests passed\n');
process.exitCode = failed ? 1 : 0;
