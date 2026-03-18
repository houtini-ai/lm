#!/usr/bin/env node
/**
 * Token Savings Benchmark for houtini-lm
 *
 * Measures whether delegating to a local LLM actually saves Claude tokens
 * using REAL source files and realistic delegation patterns.
 *
 * The cost model accounts for:
 *   1. Claude context tokens — reading a file into context costs tokens even
 *      if Claude doesn't generate anything from it. Delegating that read to
 *      the local LLM avoids this entirely.
 *   2. Claude output tokens — generation Claude doesn't have to do.
 *   3. Delegation overhead — ~250 tokens per MCP tool call (schema + envelope).
 *   4. Review cost — Claude still reads the local LLM's summary/result.
 *   5. Rate limit preservation — not measured in tokens, but noted.
 *
 * Token estimation: ~4 chars/token (conservative for code + English mix).
 */

import { readFileSync } from 'fs';
import { join } from 'path';

const BASE = process.env.LM_STUDIO_URL || 'http://localhost:1234';
const DELEGATION_OVERHEAD = 250; // MCP tool call envelope (tokens)

// ── Helpers ──────────────────────────────────────────────────────────

async function chat(messages, opts = {}) {
  const body = {
    messages,
    temperature: opts.temperature ?? 0.2,
    max_tokens: opts.max_tokens ?? 2048,
    stream: false,
  };

  const start = Date.now();
  const res = await fetch(`${BASE}/v1/chat/completions`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
    signal: AbortSignal.timeout(180000),
  });
  const elapsed = Date.now() - start;

  if (!res.ok) {
    const text = await res.text().catch(() => '');
    throw new Error(`HTTP ${res.status}: ${text}`);
  }

  const data = await res.json();
  return { ...data, elapsedMs: elapsed };
}

function tok(text) {
  return Math.ceil((text || '').length / 4);
}

function loadFile(path) {
  return readFileSync(path, 'utf-8');
}

// ── Real source files ────────────────────────────────────────────────

const FILES = {
  indexTs: loadFile(join('C:/MCP/houtini-lm/src/index.ts')),
  modelCache: loadFile(join('C:/MCP/houtini-lm/src/model-cache.ts')),
  geminiService: loadFile(join('C:/MCP/gemini-mcp/src/services/gemini/index.ts')),
  imagePrompt: loadFile(join('C:/MCP/gemini-mcp/src/tools/image-prompt-assistant.ts')),
};

console.log('\nSource files loaded:');
for (const [name, content] of Object.entries(FILES)) {
  const lines = content.split('\n').length;
  console.log(`  ${name}: ${lines} lines, ~${tok(content)} tokens`);
}

// ── Benchmark tasks ─────────────────────────────────────────────────
// Each task models a realistic delegation pattern.
//
// claudeDirectCost: what Claude would spend if it did this itself
//   = context tokens (reading the file) + output tokens (generating the answer)
//
// delegationCost (computed after): overhead + review of local LLM result
//   The key insight: Claude never reads the source file at all when delegating.

const tasks = [
  // ── Pattern 1: Full file code review (the bread and butter) ────────
  {
    name: 'Code review: index.ts (1352 lines)',
    file: 'indexTs',
    claudeContextTokens: tok(FILES.indexTs),  // Claude reads the whole file
    claudeOutputEstimate: 500,                // Claude writes a review
    messages: [
      { role: 'system', content: 'Senior TypeScript code reviewer. Find bugs, security issues, and performance problems. Be specific — reference function names and line patterns. Max 10 bullet points, no preamble.' },
      { role: 'user', content: `Review this MCP server for bugs and issues:\n\n\`\`\`typescript\n${FILES.indexTs}\n\`\`\`` },
    ],
    maxTokens: 1024,
  },

  // ── Pattern 2: Cross-file architecture review ──────────────────────
  {
    name: 'Architecture review: 2 files (2022 lines)',
    file: 'indexTs+modelCache',
    claudeContextTokens: tok(FILES.indexTs) + tok(FILES.modelCache),
    claudeOutputEstimate: 400,
    messages: [
      { role: 'system', content: 'Software architect reviewing a TypeScript MCP server. Focus on: separation of concerns, error handling patterns, API surface design. Max 8 bullet points.' },
      { role: 'user', content: `Here are the context files for analysis:\n\n--- src/index.ts ---\n\`\`\`typescript\n${FILES.indexTs}\n\`\`\`\n\n--- src/model-cache.ts ---\n\`\`\`typescript\n${FILES.modelCache}\n\`\`\`` },
    ],
    maxTokens: 1024,
  },

  // ── Pattern 3: Review an unfamiliar codebase ──────────────────────
  {
    name: 'Review external repo: gemini service (581 lines)',
    file: 'geminiService',
    claudeContextTokens: tok(FILES.geminiService),
    claudeOutputEstimate: 400,
    messages: [
      { role: 'system', content: 'Senior TypeScript reviewer. You are reviewing code you have never seen before. Identify: error handling gaps, potential crashes, resource leaks, API misuse. Max 8 bullet points, reference function names.' },
      { role: 'user', content: `Review this Gemini API service for issues:\n\n\`\`\`typescript\n${FILES.geminiService}\n\`\`\`` },
    ],
    maxTokens: 1024,
  },

  // ── Pattern 4: Generate test stubs for a real file ────────────────
  {
    name: 'Generate test stubs: model-cache.ts (670 lines)',
    file: 'modelCache',
    claudeContextTokens: tok(FILES.modelCache),
    claudeOutputEstimate: 800,
    messages: [
      { role: 'system', content: 'Senior TypeScript test engineer. Output ONLY code. Use vitest. Include describe blocks, test names, and placeholder assertions. Cover all exported functions.' },
      { role: 'user', content: `Write comprehensive test stubs for this module:\n\n\`\`\`typescript\n${FILES.modelCache}\n\`\`\`` },
    ],
    maxTokens: 2048,
  },

  // ── Pattern 5: Explain unfamiliar code ────────────────────────────
  {
    name: 'Explain code: image-prompt-assistant (833 lines)',
    file: 'imagePrompt',
    claudeContextTokens: tok(FILES.imagePrompt),
    claudeOutputEstimate: 500,
    messages: [
      { role: 'system', content: 'Technical writer explaining code to a developer joining the project. Cover: purpose, main functions, data flow, key design decisions. Use headings and bullet points. Max 500 words.' },
      { role: 'user', content: `Explain this module:\n\n\`\`\`typescript\n${FILES.imagePrompt}\n\`\`\`` },
    ],
    maxTokens: 1024,
  },

  // ── Pattern 6: Extract types / API surface ────────────────────────
  {
    name: 'Extract API surface: index.ts → type definitions',
    file: 'indexTs',
    claudeContextTokens: tok(FILES.indexTs),
    claudeOutputEstimate: 600,
    messages: [
      { role: 'system', content: 'TypeScript expert. Output ONLY TypeScript type definitions and interfaces. No implementations, no comments.' },
      { role: 'user', content: `Extract all interfaces, types, and exported function signatures from this file as a .d.ts:\n\n\`\`\`typescript\n${FILES.indexTs}\n\`\`\`` },
    ],
    maxTokens: 1024,
  },
];

// ── Run benchmark ────────────────────────────────────────────────────

console.log('\n╔══════════════════════════════════════════════════════════════════╗');
console.log('║       houtini-lm Token Savings Benchmark (Realistic)          ║');
console.log('╚══════════════════════════════════════════════════════════════════╝\n');
console.log(`Endpoint: ${BASE}`);
console.log(`Delegation overhead: ~${DELEGATION_OVERHEAD} tokens per call`);
console.log(`Tasks: ${tasks.length} realistic delegation patterns using real source files\n`);

let totalClaudeDirect = 0;
let totalDelegationCost = 0;
let totalLocalTokens = 0;
let totalSavedContext = 0;
let tasksPassed = 0;

const results = [];

for (const task of tasks) {
  process.stdout.write(`  ${task.name}...\n    `);
  try {
    const result = await chat(task.messages, { max_tokens: task.maxTokens });
    const content = result.choices[0]?.message?.content || '';
    const usage = result.usage || {};
    const localTotal = (usage.prompt_tokens || 0) + (usage.completion_tokens || 0);

    // ── Cost model ──────────────────────────────────────────────────
    // Claude DIRECT: reads the file into context + generates the answer
    const claudeDirect = task.claudeContextTokens + task.claudeOutputEstimate;

    // Claude DELEGATED: tool call overhead + reads the local LLM's result
    const reviewTokens = tok(content);
    const delegationCost = DELEGATION_OVERHEAD + reviewTokens;

    // Context tokens saved = file never enters Claude's context window
    const contextSaved = task.claudeContextTokens;

    const netSaved = claudeDirect - delegationCost;
    const pct = claudeDirect > 0 ? ((netSaved / claudeDirect) * 100).toFixed(0) : 0;

    totalClaudeDirect += claudeDirect;
    totalDelegationCost += delegationCost;
    totalLocalTokens += localTotal;
    totalSavedContext += contextSaved;
    tasksPassed++;

    const tokPerSec = usage.completion_tokens && result.elapsedMs > 100
      ? (usage.completion_tokens / (result.elapsedMs / 1000)).toFixed(1)
      : '?';

    results.push({ name: task.name, claudeDirect, delegationCost, netSaved, pct, localTotal, elapsed: result.elapsedMs, contextSaved });

    const icon = netSaved > 0 ? '✓' : '✗';
    console.log(`${icon} Claude saves ~${netSaved} tokens (${pct}%) | context avoided: ${contextSaved} | local: ${localTotal} tok @ ${tokPerSec} tok/s, ${(result.elapsedMs / 1000).toFixed(1)}s`);
  } catch (err) {
    console.log(`FAIL: ${err.message.slice(0, 100)}`);
    results.push({ name: task.name, failed: true });
  }
}

// ── Summary ──────────────────────────────────────────────────────────

const totalSaved = totalClaudeDirect - totalDelegationCost;
const overallPct = totalClaudeDirect > 0
  ? ((totalSaved / totalClaudeDirect) * 100).toFixed(1)
  : 0;

console.log('\n════════════════════════════════════════════════════════════════════');
console.log('  RESULTS');
console.log('════════════════════════════════════════════════════════════════════');
console.log('');
console.log('  Per-task breakdown:');
console.log('  ┌─────────────────────────────────────────────┬──────────┬──────────┬─────────┐');
console.log('  │ Task                                        │ Direct   │ Deleg.   │ Saved   │');
console.log('  ├─────────────────────────────────────────────┼──────────┼──────────┼─────────┤');
for (const r of results) {
  if (r.failed) {
    console.log(`  │ ${r.name.padEnd(43)} │ FAILED   │          │         │`);
  } else {
    console.log(`  │ ${r.name.slice(0, 43).padEnd(43)} │ ${String(r.claudeDirect).padStart(6)}tk │ ${String(r.delegationCost).padStart(6)}tk │ ${(r.pct + '%').padStart(5)}   │`);
  }
}
console.log('  └─────────────────────────────────────────────┴──────────┴──────────┴─────────┘');
console.log('');
console.log(`  Tasks completed:           ${tasksPassed}/${tasks.length}`);
console.log(`  Claude direct cost:        ~${totalClaudeDirect} tokens`);
console.log(`  Delegation cost:           ~${totalDelegationCost} tokens`);
console.log(`  Context tokens avoided:    ~${totalSavedContext} tokens (files Claude never had to read)`);
console.log(`  Tokens offloaded to local: ${totalLocalTokens} tokens (free — runs on your hardware)`);
console.log(`  Net Claude tokens saved:   ~${totalSaved} tokens (${overallPct}%)`);
console.log('');

if (totalSaved > 0) {
  // Extrapolate to a realistic session
  const sessionsPerDay = 3;
  const tasksPerSession = tasksPassed;
  const dailySaved = totalSaved * sessionsPerDay;
  const monthlySaved = dailySaved * 22; // working days
  const costPerMTok = 15; // Claude output $/MTok
  const monthlyCostSaved = (monthlySaved / 1_000_000) * costPerMTok;

  console.log('  ✓ DELEGATION SAVES TOKENS');
  console.log('');
  console.log('  Extrapolated savings:');
  console.log(`    Per session (${tasksPerSession} delegations):  ~${totalSaved} tokens saved`);
  console.log(`    Per day (${sessionsPerDay} sessions):          ~${dailySaved.toLocaleString()} tokens saved`);
  console.log(`    Per month (22 work days):       ~${monthlySaved.toLocaleString()} tokens saved`);
  console.log(`    Monthly cost savings:           ~$${monthlyCostSaved.toFixed(2)} at $${costPerMTok}/MTok`);
  console.log('');
  console.log('  Beyond token counts, delegation also:');
  console.log('    • Preserves Claude rate limits for higher-value interactive work');
  console.log('    • Enables parallel execution (local LLM works while Claude does other things)');
  console.log('    • Keeps large files out of Claude context window (avoids compression/truncation)');
} else {
  console.log('  ✗ Delegation did not save tokens overall.');
  console.log('    This is unusual for file-level tasks — check that the local LLM completed all tasks.');
}

console.log('\n════════════════════════════════════════════════════════════════════\n');
process.exit(tasksPassed === tasks.length ? 0 : 1);
