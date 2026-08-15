#!/usr/bin/env node
/**
 * Derive a prompting schema for a model from its HuggingFace repo.
 *
 * WHY
 * getPromptHints() in src/model-cache.ts is a hand-maintained regex table. Any model
 * newer than the table falls through to bland defaults, and those defaults are not
 * neutral - they are actively wrong for some families.
 *
 * Measured on 2026-08-12 with Nemotron 3 Super 120B: run with the defaults (temp 0.3,
 * no thinking control, no output constraint) it completed 2 of 6 build phases, burned
 * 58,747 output tokens and produced 334 usable lines. Run with settings taken from its
 * own model card it completed 6 of 6, used 18,481 tokens and produced 1,780 lines.
 * Same model, same hardware, same prompts. 68% fewer tokens for 5x the output.
 *
 * Every fact needed for that fix was sitting in the repo:
 *   - temperature 1.0 / top_p 0.95      -> README prose
 *   - enable_thinking=True/False        -> README + chat_template
 *   - reasoning parser name             -> README
 *   - architecture                      -> config JSON
 *
 * houtini-lm already calls the JSON metadata endpoint. It does not fetch README.md,
 * which is where the sampling and thinking guidance lives.
 *
 * USAGE
 *   node scripts/derive-prompt-schema.mjs <hf-model-id> [--json]
 */

const HF_TOKEN = process.env.HF_TOKEN || '';
const headers = { Accept: 'application/json', ...(HF_TOKEN ? { Authorization: `Bearer ${HF_TOKEN}` } : {}) };

async function get(url, asJson) {
  const res = await fetch(url, { headers, signal: AbortSignal.timeout(15000) });
  if (!res.ok) return null;
  return asJson ? res.json() : res.text();
}

/** Sampling recommendations. Cards often list several (thinking vs non-thinking), so
 *  capture them with surrounding context rather than trusting the first number. */
function extractSampling(md) {
  const out = { candidates: [], recommended: null };
  const re = /(?:^|\n)([^\n]{0,120}?)[Tt]emperature[ =:]+([0-9.]+)([^\n]{0,120})/g;
  let m;
  while ((m = re.exec(md))) {
    const ctx = (m[1] + m[3]).toLowerCase();
    const topP = /top[_ ]?p[ =:]+([0-9.]+)/.exec(m[3]) || /top[_ ]?p[ =:]+([0-9.]+)/.exec(m[1]);
    out.candidates.push({
      temperature: parseFloat(m[2]),
      top_p: topP ? parseFloat(topP[1]) : null,
      // a card that says "for coding" or "for tool use" is the one we want
      forCode: /cod(e|ing)|tool|agent|program/.test(ctx),
      thinkingMode: /think|reason/.test(ctx) ? true : (/non-?think|no.?think/.test(ctx) ? false : null),
      context: (m[1] + 'temperature=' + m[2] + m[3]).trim().slice(0, 140),
    });
  }
  out.recommended = out.candidates.find(c => c.forCode) || out.candidates[0] || null;
  return out;
}

/** How reasoning is turned off. The chat template is authoritative: if it branches on
 *  enable_thinking, the kwarg works, whatever the prose says. */
function extractThinking(md, chatTemplate) {
  const templateSupports = !!chatTemplate && /enable_thinking/.test(chatTemplate);
  const readmeMentions = /enable_thinking/.test(md);
  const legacyPrompt = /detailed thinking (on|off)/i.test(md);
  let mechanism = 'none';
  if (templateSupports || readmeMentions) mechanism = 'chat_template_kwargs.enable_thinking=false';
  else if (legacyPrompt) mechanism = 'system-prompt (LEGACY - verify, deprecated in newer generations)';
  return {
    mechanism,
    templateSupports,
    readmeMentions,
    legacyPromptMentioned: legacyPrompt,
    // A card mentioning BOTH is the trap that cost us a day: the legacy prompt is
    // deprecated but still documented, and testing it "proves" thinking cannot be
    // disabled when the kwarg works perfectly.
    ambiguous: legacyPrompt && (templateSupports || readmeMentions),
  };
}

function extractServerFlags(md) {
  const grab = (re) => { const m = re.exec(md); return m ? m[1].trim() : null; };
  return {
    reasoningParser: grab(/--reasoning[-_]parser[ =]+([\w.-]+)/),
    toolCallParser: grab(/--tool[-_]call[-_]parser[ =]+([\w.-]+)/),
    needsExpertParallel: /--enable-expert-parallel/.test(md),
    minVllm: grab(/vllm[>=~ ]+v?([0-9]+\.[0-9]+(?:\.[0-9]+)?)/i),
  };
}

/** Does the model fence code by default, or must you demand it? */
function extractOutputHabits(md) {
  const stripsMarkdown = /strip|without (?:any )?markdown|raw (?:json|output)|no (?:markdown|formatting)|pure structured/i.test(md);
  const agentTuned = /agent(ic)? workflow|programmatic|structured output|function call/i.test(md);
  return {
    likelyStripsFences: stripsMarkdown || agentTuned,
    outputConstraint: (stripsMarkdown || agentTuned)
      ? 'Wrap code in a markdown fence: begin with three backticks followed by the language, and end with three backticks. Output nothing outside the fence.'
      : '',
    evidence: { stripsMarkdown, agentTuned },
  };
}

async function derive(modelId) {
  const meta = await get(`https://huggingface.co/api/models/${modelId}`, true);
  let md = '';
  for (const branch of ['main', 'master']) {
    md = (await get(`https://huggingface.co/${modelId}/raw/${branch}/README.md`, false)) || '';
    if (md) break;
  }
  const chatTemplate = meta?.config?.tokenizer_config?.chat_template || '';
  const sampling = extractSampling(md);

  return {
    modelId,
    architecture: meta?.config?.architectures?.[0] || null,
    license: meta?.cardData?.license || null,
    readmeChars: md.length,
    sampling,
    thinking: extractThinking(md, chatTemplate),
    serverFlags: extractServerFlags(md),
    output: extractOutputHabits(md),
    // Anything unresolved is flagged rather than guessed. A guessed default is what
    // cost 40k tokens; an explicit "unknown" prompts a human to look.
    needsHumanReview: [
      !sampling.recommended && 'no sampling recommendation found',
      sampling.candidates.length > 2 && 'multiple sampling profiles - confirm which applies to your task',
      !md.length && 'no README retrieved',
    ].filter(Boolean),
  };
}

const id = process.argv[2];
if (!id) { console.error('usage: derive-prompt-schema.mjs <hf-model-id> [--json]'); process.exit(1); }

const schema = await derive(id);
if (process.argv.includes('--json')) {
  console.log(JSON.stringify(schema, null, 2));
} else {
  console.log(`\n  ${schema.modelId}`);
  console.log(`  arch: ${schema.architecture}   licence: ${schema.license}   README: ${schema.readmeChars} chars\n`);
  const s = schema.sampling.recommended;
  console.log(`  sampling      : ${s ? `temp ${s.temperature}, top_p ${s.top_p ?? '-'}${s.forCode ? '  (code/tool context)' : ''}` : 'NOT FOUND'}`);
  console.log(`  reasoning off : ${schema.thinking.mechanism}${schema.thinking.ambiguous ? '   [!] card documents BOTH new and legacy methods' : ''}`);
  console.log(`  reasoning-parser: ${schema.serverFlags.reasoningParser || '-'}    tool-parser: ${schema.serverFlags.toolCallParser || '-'}`);
  console.log(`  fences code   : ${schema.output.likelyStripsFences ? 'NO - demand a fence explicitly' : 'probably'}`);
  if (schema.needsHumanReview.length) console.log(`\n  REVIEW: ${schema.needsHumanReview.join('; ')}`);
  console.log('');
}
