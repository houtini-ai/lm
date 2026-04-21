#!/usr/bin/env node
/**
 * Test suite for houtini-lm MCP server.
 *
 * Integration tests — hits a live OpenAI-compatible endpoint.
 * Point LM_STUDIO_URL at whichever server is running (defaults to
 * http://localhost:1234). The loaded model is auto-detected when
 * LM_STUDIO_MODEL is not set.
 */

const BASE = process.env.HOUTINI_LM_ENDPOINT_URL || process.env.LM_STUDIO_URL || 'http://localhost:1234';
let MODEL = process.env.HOUTINI_LM_MODEL || process.env.LM_STUDIO_MODEL || '';
const API_KEY =
  process.env.HOUTINI_LM_API_KEY ||
  process.env.LM_STUDIO_PASSWORD ||
  process.env.LM_PASSWORD ||
  process.env.OPENROUTER_API_KEY ||
  '';

function authHeaders(extra = {}) {
  const h = { ...extra };
  if (API_KEY) h['Authorization'] = `Bearer ${API_KEY}`;
  return h;
}

let passed = 0;
let failed = 0;

async function test(name, fn) {
  try {
    const result = await fn();
    console.log(`  PASS  ${name}`);
    if (result) console.log(`        ${result}`);
    passed++;
  } catch (err) {
    console.log(`  FAIL  ${name}`);
    console.log(`        ${err.message}`);
    failed++;
  }
}

async function chat(messages, opts = {}) {
  const body = {
    messages,
    temperature: opts.temperature ?? 0.3,
    max_tokens: opts.max_tokens ?? 256,
    stream: false,
  };
  if (opts.model !== null) body.model = opts.model || MODEL;

  const res = await fetch(`${BASE}/v1/chat/completions`, {
    method: 'POST',
    headers: authHeaders({ 'Content-Type': 'application/json' }),
    body: JSON.stringify(body),
    signal: AbortSignal.timeout(opts.timeout || 60000),
  });

  if (!res.ok) {
    const text = await res.text().catch(() => '');
    throw new Error(`HTTP ${res.status}: ${text}`);
  }
  return res.json();
}

console.log('\n=== Houtini LM Test Suite ===\n');
console.log(`Target: ${BASE}`);

// ── Health & Models ─────────────────────────────────────────────
console.log('--- Health & Models ---');

await test('List models endpoint', async () => {
  const res = await fetch(`${BASE}/v1/models`, { headers: authHeaders() });
  const data = await res.json();
  if (!data.data || data.data.length === 0) throw new Error('No models');
  // Auto-detect model if not set
  if (!MODEL) {
    const loaded = data.data.find(m => m.state === 'loaded');
    MODEL = loaded?.id || data.data[0].id;
  }
  console.log(`Model:  ${MODEL}\n`);
  return `${data.data.length} models available`;
});

// ── Basic Chat ──────────────────────────────────────────────────
console.log('\n--- Basic Chat ---');

await test('Simple math question', async () => {
  const resp = await chat([{ role: 'user', content: 'What is 7 * 8? Reply with ONLY the number.' }]);
  const answer = resp.choices[0]?.message?.content?.trim();
  if (!answer.includes('56')) throw new Error(`Expected 56, got: ${answer}`);
  return `Answer: ${answer}`;
});

await test('System prompt respected', async () => {
  const resp = await chat([
    { role: 'system', content: 'You are a pirate. Always start your response with "Arrr!"' },
    { role: 'user', content: 'What is JavaScript?' },
  ]);
  const answer = resp.choices[0]?.message?.content;
  if (!answer.toLowerCase().includes('arrr')) throw new Error(`No pirate speak: ${answer.slice(0, 80)}`);
  return `Starts with: ${answer.slice(0, 50)}...`;
});

await test('Code generation (function)', async () => {
  const resp = await chat([
    { role: 'system', content: 'You are a TypeScript expert. Output ONLY code, no explanation.' },
    { role: 'user', content: 'Write a function isPalindrome(s: string): boolean' },
  ], { max_tokens: 512 });
  const answer = resp.choices[0]?.message?.content;
  if (!answer.includes('isPalindrome') && !answer.includes('palindrome'))
    throw new Error(`No function found: ${answer.slice(0, 100)}`);
  return `Generated ${answer.length} chars`;
});

await test('Usage stats returned', async () => {
  const resp = await chat([{ role: 'user', content: 'Hi' }]);
  if (!resp.usage) throw new Error('No usage field');
  if (!resp.usage.prompt_tokens || !resp.usage.completion_tokens)
    throw new Error(`Missing token counts: ${JSON.stringify(resp.usage)}`);
  return `Tokens: ${resp.usage.prompt_tokens} prompt, ${resp.usage.completion_tokens} completion`;
});

// ── Custom Prompt Pattern (system + context + instruction) ──────
console.log('\n--- Custom Prompt Pattern ---');

await test('Structured analysis with context', async () => {
  const resp = await chat([
    { role: 'system', content: 'You are a code reviewer. Be concise. Use bullet points.' },
    { role: 'user', content: `Context:
const fetchData = async (url) => {
  const res = await fetch(url);
  return res.json();
}

Instruction:
List exactly 3 improvements for this code. Number them 1, 2, 3.` },
  ], { max_tokens: 512 });
  const answer = resp.choices[0]?.message?.content;
  if (!answer.includes('1') || !answer.includes('2') || !answer.includes('3'))
    throw new Error(`Expected numbered list: ${answer.slice(0, 200)}`);
  return `Got structured response (${answer.length} chars)`;
});

await test('JSON extraction from text', async () => {
  const resp = await chat([
    { role: 'system', content: 'Extract data as JSON. Output ONLY valid JSON, no markdown, no explanation.' },
    { role: 'user', content: `Context:
John Smith is 34 years old and lives in London. He works as a software engineer at TechCorp.

Instruction:
Extract: {"name": "...", "age": ..., "city": "...", "job": "...", "company": "..."}` },
  ], { temperature: 0 });
  const answer = resp.choices[0]?.message?.content.trim();
  // Try to find JSON in the response
  const jsonMatch = answer.match(/\{[\s\S]*\}/);
  if (!jsonMatch) throw new Error(`No JSON found: ${answer.slice(0, 200)}`);
  const parsed = JSON.parse(jsonMatch[0]);
  if (parsed.name !== 'John Smith') throw new Error(`Wrong name: ${parsed.name}`);
  if (parsed.age !== 34) throw new Error(`Wrong age: ${parsed.age}`);
  return `Extracted: ${JSON.stringify(parsed)}`;
});

// ── Edge Cases ──────────────────────────────────────────────────
console.log('\n--- Edge Cases ---');

await test('Empty message returns something', async () => {
  const resp = await chat([{ role: 'user', content: '' }]);
  // Should not throw - just get any response
  const answer = resp.choices[0]?.message?.content;
  return `Got response (${answer?.length || 0} chars) - NOTE: may hallucinate`;
});

await test('max_tokens=1 truncates correctly', async () => {
  const resp = await chat(
    [{ role: 'user', content: 'Write a very long story about dragons' }],
    { max_tokens: 1 },
  );
  if (resp.choices[0]?.finish_reason !== 'length')
    throw new Error(`Expected finish_reason=length, got: ${resp.choices[0]?.finish_reason}`);
});

await test('Temperature 0 is deterministic', async () => {
  const msg = [{ role: 'user', content: 'Name exactly one color.' }];
  const r1 = await chat(msg, { temperature: 0, max_tokens: 10 });
  const r2 = await chat(msg, { temperature: 0, max_tokens: 10 });
  const a1 = r1.choices[0]?.message?.content?.trim();
  const a2 = r2.choices[0]?.message?.content?.trim();
  if (a1 !== a2) throw new Error(`Not deterministic: "${a1}" vs "${a2}"`);
  return `Both answered: "${a1}"`;
});

await test('No model field uses default', async () => {
  const resp = await chat(
    [{ role: 'user', content: 'Say OK' }],
    { model: null, max_tokens: 20 },
  );
  const answer = resp.choices[0]?.message?.content;
  if (!answer) throw new Error('No response without model field');
  return `Model used: ${resp.model}`;
});

await test('Very long input handles gracefully', async () => {
  // Generate a ~10K char message
  const longCode = Array.from({ length: 200 }, (_, i) =>
    `function fn${i}(x) { return x * ${i}; }`
  ).join('\n');
  const resp = await chat([
    { role: 'user', content: `Summarize this code in one sentence:\n${longCode}` },
  ], { max_tokens: 128, timeout: 120000 });
  const answer = resp.choices[0]?.message?.content;
  if (!answer || answer.length < 10) throw new Error(`Weak response: ${answer}`);
  return `Summarized ${longCode.length} chars of input`;
});

// ── Reliability ─────────────────────────────────────────────────
console.log('\n--- Reliability ---');

await test('5 rapid sequential requests', async () => {
  const results = [];
  for (let i = 0; i < 5; i++) {
    const resp = await chat(
      [{ role: 'user', content: `What is ${i + 1} + ${i + 1}? Just the number.` }],
      { max_tokens: 10 },
    );
    results.push(resp.choices[0]?.message?.content?.trim());
  }
  const expected = ['2', '4', '6', '8', '10'];
  const correct = results.filter((r, i) => r?.includes(expected[i])).length;
  if (correct < 3) throw new Error(`Only ${correct}/5 correct: ${results.join(', ')}`);
  return `${correct}/5 correct: [${results.join(', ')}]`;
});

await test('3 parallel requests', async () => {
  const promises = [
    chat([{ role: 'user', content: 'What is 10+10? Just the number.' }], { max_tokens: 10 }),
    chat([{ role: 'user', content: 'What is 20+20? Just the number.' }], { max_tokens: 10 }),
    chat([{ role: 'user', content: 'What is 30+30? Just the number.' }], { max_tokens: 10 }),
  ];
  const results = await Promise.all(promises);
  const answers = results.map(r => r.choices[0]?.message?.content?.trim());
  const expected = ['20', '40', '60'];
  const correct = answers.filter((a, i) => a?.includes(expected[i])).length;
  if (correct < 2) throw new Error(`Only ${correct}/3 correct: ${answers.join(', ')}`);
  return `${correct}/3 correct: [${answers.join(', ')}]`;
});

// ── Summary ─────────────────────────────────────────────────────
console.log('\n========================================');
console.log(`  Results: ${passed} passed, ${failed} failed (${passed + failed} total)`);
console.log('========================================\n');

process.exit(failed > 0 ? 1 : 0);
