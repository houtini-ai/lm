#!/usr/bin/env node
/**
 * Houtini LM shakedown — self-test & benchmark
 *
 * Runs the 7-step sequence end-to-end against the configured LM Studio /
 * Ollama / OpenAI-compatible endpoint, captures real TTFT / tok/s / reasoning
 * split from each call, and prints a markdown summary. This is the canonical
 * way to verify an install and get an honest read on what the local model
 * can do on this workstation.
 *
 * Usage:
 *   LM_STUDIO_URL=http://host:1234 node shakedown.mjs
 *   # or simply:
 *   npm run shakedown
 *
 * The script talks directly to the OpenAI-compatible /v1 endpoint (same
 * transport houtini-lm uses for every call) so latency here matches what
 * you'd see through the MCP server.
 */

import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const BASE = process.env.LM_STUDIO_URL || 'http://localhost:1234';
const REPO = dirname(fileURLToPath(import.meta.url));

// ── Backend probe ─────────────────────────────────────────────────────
// Mirrors the three-endpoint probe in src/index.ts listModelsRaw.

async function detectBackend() {
  // LM Studio /api/v0/models — richest metadata
  try {
    const res = await fetch(`${BASE}/api/v0/models`, { signal: AbortSignal.timeout(5000) });
    if (res.ok) {
      const data = await res.json();
      return { backend: 'LM Studio', models: data.data };
    }
  } catch { /* fall through */ }

  // Ollama /api/tags
  try {
    const res = await fetch(`${BASE}/api/tags`, { signal: AbortSignal.timeout(5000) });
    if (res.ok) {
      const data = await res.json();
      if (Array.isArray(data.models)) {
        return {
          backend: 'Ollama',
          models: data.models.map((m) => ({
            id: m.name,
            arch: m.details?.family,
            quantization: m.details?.quantization_level,
            state: 'loaded',
          })),
        };
      }
    }
  } catch { /* fall through */ }

  // Generic /v1/models
  const res = await fetch(`${BASE}/v1/models`, { signal: AbortSignal.timeout(5000) });
  if (!res.ok) throw new Error(`Cannot reach ${BASE} — HTTP ${res.status}`);
  const data = await res.json();
  return { backend: 'OpenAI-compatible', models: data.data };
}

// ── Streaming chat with TTFT / tok/s capture ───────────────────────────
// Shape-matches what the server does internally: SSE streaming, capture
// delta.content AND delta.reasoning_content, read usage.completion_tokens_details
// when present.

function reasoningEffortValue(backend) {
  if (backend === 'LM Studio' || backend === 'Ollama') return 'none';
  return 'low';
}

async function streamingChat({ messages, model, backend, temperature = 0.3, maxTokens, responseFormat }) {
  const body = {
    model,
    messages,
    temperature,
    max_tokens: maxTokens ?? 16384,
    max_completion_tokens: maxTokens ?? 16384,
    stream: true,
    stream_options: { include_usage: true },
    reasoning_effort: reasoningEffortValue(backend),
    enable_thinking: false,
  };
  if (responseFormat) body.response_format = responseFormat;

  const start = Date.now();
  const res = await fetch(`${BASE}/v1/chat/completions`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
    signal: AbortSignal.timeout(300_000),
  });

  if (!res.ok) {
    const text = await res.text().catch(() => '');
    throw new Error(`HTTP ${res.status}: ${text}`);
  }

  const reader = res.body.getReader();
  const decoder = new TextDecoder();
  let content = '';
  let reasoning = '';
  let usage = null;
  let buffer = '';
  let ttftMs;

  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    buffer += decoder.decode(value, { stream: true });
    const lines = buffer.split('\n');
    buffer = lines.pop() || '';
    for (const line of lines) {
      const trimmed = line.trim();
      if (!trimmed || trimmed === 'data: [DONE]' || !trimmed.startsWith('data: ')) continue;
      try {
        const json = JSON.parse(trimmed.slice(6));
        const delta = json.choices?.[0]?.delta;
        if (typeof delta?.reasoning_content === 'string') reasoning += delta.reasoning_content;
        if (typeof delta?.content === 'string' && delta.content.length > 0) {
          if (ttftMs === undefined) ttftMs = Date.now() - start;
          content += delta.content;
        }
        if (json.usage) usage = json.usage;
      } catch { /* skip unparseable */ }
    }
  }

  // Strip <think>...</think> blocks from content
  let clean = content.replace(/<think>[\s\S]*?<\/think>\s*/g, '');
  clean = clean.replace(/^<think>\s*/, '').trim();

  const generationMs = Date.now() - start;
  const tokPerSec = usage && generationMs > 50
    ? usage.completion_tokens / (generationMs / 1000)
    : null;

  return {
    content: clean,
    rawContent: content,
    reasoning,
    usage,
    ttftMs,
    generationMs,
    tokPerSec,
  };
}

// ── Step runner ───────────────────────────────────────────────────────

const results = [];

function recordResult(tool, {
  ok, ttftMs, tokPerSec, promptTokens, completionTokens, reasoningTokens, notes,
}) {
  results.push({ tool, ok, ttftMs, tokPerSec, promptTokens, completionTokens, reasoningTokens, notes });
}

function hr(label) {
  console.log(`\n${'─'.repeat(70)}\n${label}\n${'─'.repeat(70)}`);
}

// ── Shakedown steps ───────────────────────────────────────────────────

async function main() {
  console.log(`\n🧪 Houtini LM shakedown`);
  console.log(`   Endpoint: ${BASE}`);

  // Step 1: discover
  hr('1. discover — endpoint + active model');
  let backend, models;
  try {
    const probe = await detectBackend();
    backend = probe.backend;
    models = probe.models;
    const loaded = models.filter((m) => m.state === 'loaded' || !m.state);
    const unloaded = models.filter((m) => m.state === 'not-loaded');
    console.log(`   Backend detected: ${backend}`);
    console.log(`   Loaded models: ${loaded.length}`);
    console.log(`   Downloaded (not loaded): ${unloaded.length}`);
    if (loaded[0]) {
      console.log(`   Active: ${loaded[0].id}`);
      if (loaded[0].loaded_context_length) console.log(`   Context window: ${loaded[0].loaded_context_length.toLocaleString()}`);
    }
    recordResult('discover', { ok: true, notes: `${backend}, ${loaded.length} loaded, ${unloaded.length} available` });
  } catch (err) {
    console.log(`   ❌ FAILED: ${err.message}`);
    recordResult('discover', { ok: false, notes: err.message });
    console.log('\n   Cannot reach endpoint — aborting shakedown.');
    process.exit(1);
  }

  const loadedLlm = models.find((m) => (m.state === 'loaded' || !m.state) && m.type !== 'embeddings');
  const loadedEmbed = models.find((m) => (m.state === 'loaded' || !m.state) && m.type === 'embeddings');
  const chatModel = loadedLlm?.id;

  if (!chatModel) {
    console.log('\n   No chat-capable model loaded. Load one and re-run.');
    process.exit(1);
  }

  // Step 2: list_models (summary)
  hr('2. list_models — loaded vs available');
  for (const m of models) {
    const mark = (m.state === 'loaded' || !m.state) ? '●' : '○';
    const meta = [m.type, m.arch, m.quantization].filter(Boolean).join(' · ');
    console.log(`   ${mark} ${m.id}${meta ? '    ' + meta : ''}`);
  }
  recordResult('list_models', { ok: true, notes: `${models.length} total` });

  // Step 3: chat sanity check
  hr('3. chat — WebSockets vs SSE sanity check');
  try {
    const resp = await streamingChat({
      backend,
      model: chatModel,
      temperature: 0.3,
      maxTokens: 2000,
      messages: [
        { role: 'system', content: 'Technical writer. Terse bullets, no preamble.' },
        { role: 'user', content: 'In 3 bullets, what are the main trade-offs between WebSockets and Server-Sent Events?' },
      ],
    });
    const reasoningTokens = resp.usage?.completion_tokens_details?.reasoning_tokens ?? 0;
    console.log(`   ${resp.content.slice(0, 300)}${resp.content.length > 300 ? '…' : ''}`);
    console.log(`   TTFT: ${resp.ttftMs}ms · ${resp.tokPerSec?.toFixed(1)} tok/s · ${resp.usage?.prompt_tokens}→${resp.usage?.completion_tokens} tokens${reasoningTokens ? ` (${reasoningTokens} reasoning)` : ''}`);
    recordResult('chat', {
      ok: true, ttftMs: resp.ttftMs, tokPerSec: resp.tokPerSec,
      promptTokens: resp.usage?.prompt_tokens, completionTokens: resp.usage?.completion_tokens,
      reasoningTokens, notes: resp.content.length > 20 ? 'answered' : 'short answer',
    });
  } catch (err) {
    console.log(`   ❌ FAILED: ${err.message}`);
    recordResult('chat', { ok: false, notes: err.message });
  }

  // Step 4: custom_prompt — structured JSON review of timedRead
  hr('4. custom_prompt — structured JSON review (forced schema)');
  const timedReadSrc = `async function timedRead(
  reader: ReadableStreamDefaultReader<Uint8Array>,
  timeoutMs: number,
): Promise<{ done: boolean; value?: Uint8Array } | 'timeout'> {
  let timer: ReturnType<typeof setTimeout>;
  const timeout = new Promise<'timeout'>((resolve) => {
    timer = setTimeout(() => resolve('timeout'), timeoutMs);
  });
  try {
    return await Promise.race([reader.read(), timeout]);
  } finally {
    clearTimeout(timer!);
  }
}`;

  try {
    const resp = await streamingChat({
      backend,
      model: chatModel,
      temperature: 0.1,
      maxTokens: 2000,
      responseFormat: {
        type: 'json_schema',
        json_schema: {
          name: 'review',
          schema: {
            type: 'array',
            items: {
              type: 'object',
              properties: {
                line: { type: 'number' },
                severity: { type: 'string', enum: ['low', 'medium', 'high'] },
                issue: { type: 'string' },
                suggestion: { type: 'string' },
              },
              required: ['line', 'severity', 'issue', 'suggestion'],
              additionalProperties: false,
            },
            maxItems: 5,
          },
        },
      },
      messages: [
        { role: 'system', content: 'Senior TypeScript reviewer, focused on error handling and edge cases. No preamble.' },
        { role: 'user', content: `Context:\n\`\`\`typescript\n${timedReadSrc}\n\`\`\`\n\nReturn a JSON array of {line, severity, issue, suggestion}. Max 5 items.` },
      ],
    });

    let validJson = false;
    let itemCount = 0;
    let severitiesValid = false;
    try {
      const parsed = JSON.parse(resp.content);
      validJson = Array.isArray(parsed);
      itemCount = parsed.length;
      severitiesValid = parsed.every((p) => ['low', 'medium', 'high'].includes(p.severity));
    } catch { /* validJson stays false */ }

    console.log(`   ${resp.content.slice(0, 200)}…`);
    console.log(`   Valid JSON: ${validJson} · Items: ${itemCount} · Severities in enum: ${severitiesValid}`);
    const reasoningTokens = resp.usage?.completion_tokens_details?.reasoning_tokens ?? 0;
    console.log(`   TTFT: ${resp.ttftMs}ms · ${resp.tokPerSec?.toFixed(1)} tok/s · ${resp.usage?.prompt_tokens}→${resp.usage?.completion_tokens} tokens${reasoningTokens ? ` (${reasoningTokens} reasoning)` : ''}`);
    recordResult('custom_prompt', {
      ok: validJson && severitiesValid, ttftMs: resp.ttftMs, tokPerSec: resp.tokPerSec,
      promptTokens: resp.usage?.prompt_tokens, completionTokens: resp.usage?.completion_tokens,
      reasoningTokens, notes: validJson ? `${itemCount} valid items` : 'invalid JSON',
    });
  } catch (err) {
    console.log(`   ❌ FAILED: ${err.message}`);
    recordResult('custom_prompt', { ok: false, notes: err.message });
  }

  // Step 5: code_task — Jest tests for getContextLength
  hr('5. code_task — Jest test generation');
  const getContextLengthSrc = `const FALLBACK_CONTEXT_LENGTH = parseInt(process.env.LM_CONTEXT_WINDOW || '100000', 10);

interface ModelInfo {
  id: string;
  loaded_context_length?: number;
  max_context_length?: number;
  context_length?: number;
  max_model_len?: number;
}

export function getContextLength(model: ModelInfo): number {
  return model.loaded_context_length ?? model.max_context_length ?? model.context_length ?? model.max_model_len ?? FALLBACK_CONTEXT_LENGTH;
}`;

  try {
    const resp = await streamingChat({
      backend,
      model: chatModel,
      temperature: 0.2,
      maxTokens: 2000,
      messages: [
        { role: 'system', content: 'Expert TypeScript developer. Write clean, runnable Jest tests. No preamble. Output only the test code in a single typescript fenced block.' },
        { role: 'user', content: `Write exactly 3 Jest tests (happy path, edge case, error path) for this function:\n\n\`\`\`typescript\n${getContextLengthSrc}\n\`\`\`` },
      ],
    });

    const looksLikeCode = /describe\s*\(|it\s*\(|test\s*\(|expect\s*\(/.test(resp.content);
    console.log(`   ${resp.content.slice(0, 200)}…`);
    console.log(`   Looks like Jest code: ${looksLikeCode}`);
    const reasoningTokens = resp.usage?.completion_tokens_details?.reasoning_tokens ?? 0;
    console.log(`   TTFT: ${resp.ttftMs}ms · ${resp.tokPerSec?.toFixed(1)} tok/s · ${resp.usage?.prompt_tokens}→${resp.usage?.completion_tokens} tokens${reasoningTokens ? ` (${reasoningTokens} reasoning)` : ''}`);
    recordResult('code_task', {
      ok: looksLikeCode, ttftMs: resp.ttftMs, tokPerSec: resp.tokPerSec,
      promptTokens: resp.usage?.prompt_tokens, completionTokens: resp.usage?.completion_tokens,
      reasoningTokens, notes: looksLikeCode ? 'tests generated' : 'no test syntax detected',
    });
  } catch (err) {
    console.log(`   ❌ FAILED: ${err.message}`);
    recordResult('code_task', { ok: false, notes: err.message });
  }

  // Step 6: code_task_files — multi-file review (reads this repo's test.mjs + benchmark.mjs)
  hr('6. code_task_files — cross-file review (test.mjs + benchmark.mjs)');
  try {
    const testSrc = await readFile(join(REPO, 'test.mjs'), 'utf8');
    const benchSrc = await readFile(join(REPO, 'benchmark.mjs'), 'utf8');
    const combined = `=== test.mjs ===\n${testSrc}\n\n=== benchmark.mjs ===\n${benchSrc}`;
    const estInputTokens = Math.ceil(combined.length / 4);
    console.log(`   Input: ~${estInputTokens.toLocaleString()} tokens across 2 files`);

    const resp = await streamingChat({
      backend,
      model: chatModel,
      temperature: 0.2,
      maxTokens: 3000,
      messages: [
        { role: 'system', content: 'Expert JavaScript reviewer. Cross-reference both files. Be specific — reference filename and line number. Output a terse numbered list, max 7 items. No preamble, no closing summary.' },
        { role: 'user', content: `Find any bug, dead code, or naming inconsistency across BOTH files. They target the same server.\n\n\`\`\`javascript\n${combined}\n\`\`\`` },
      ],
    });

    const mentionsBothFiles = /test\.mjs/i.test(resp.content) && /benchmark\.mjs/i.test(resp.content);
    console.log(`   ${resp.content.slice(0, 300)}…`);
    console.log(`   Cross-referenced both files: ${mentionsBothFiles}`);
    const reasoningTokens = resp.usage?.completion_tokens_details?.reasoning_tokens ?? 0;
    console.log(`   TTFT: ${resp.ttftMs}ms · ${resp.tokPerSec?.toFixed(1)} tok/s · ${resp.usage?.prompt_tokens}→${resp.usage?.completion_tokens} tokens${reasoningTokens ? ` (${reasoningTokens} reasoning)` : ''}`);
    recordResult('code_task_files', {
      ok: resp.content.length > 100, ttftMs: resp.ttftMs, tokPerSec: resp.tokPerSec,
      promptTokens: resp.usage?.prompt_tokens, completionTokens: resp.usage?.completion_tokens,
      reasoningTokens, notes: mentionsBothFiles ? 'cross-referenced' : 'single-file analysis only',
    });
  } catch (err) {
    console.log(`   ❌ FAILED: ${err.message}`);
    recordResult('code_task_files', { ok: false, notes: err.message });
  }

  // Step 7: embed — graceful if no embedding model loaded
  hr('7. embed — vector test');
  if (!loadedEmbed) {
    console.log(`   ⚠  No embedding model loaded. Load one (e.g. text-embedding-nomic-embed-text-v1.5) and re-run to test this step.`);
    recordResult('embed', { ok: false, notes: 'no embedding model loaded (expected — skipped gracefully)' });
  } else {
    try {
      const res = await fetch(`${BASE}/v1/embeddings`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ input: 'Large language models running locally.', model: loadedEmbed.id }),
        signal: AbortSignal.timeout(30_000),
      });
      if (!res.ok) throw new Error(`HTTP ${res.status}: ${await res.text().catch(() => '')}`);
      const data = await res.json();
      const vec = data.data?.[0]?.embedding ?? data.embedding;
      const dims = Array.isArray(vec) ? vec.length : 0;
      console.log(`   Model: ${data.model || loadedEmbed.id}`);
      console.log(`   Dimensions: ${dims}`);
      recordResult('embed', { ok: dims > 0, notes: `${dims}-dim vector` });
    } catch (err) {
      console.log(`   ❌ FAILED: ${err.message}`);
      recordResult('embed', { ok: false, notes: err.message });
    }
  }

  // ── Summary ──────────────────────────────────────────────────────
  hr('Summary');
  const passed = results.filter((r) => r.ok).length;
  console.log(`\n   ${passed}/${results.length} steps passed on ${backend}, model=${chatModel}\n`);
  console.log(`| Tool              | OK  | TTFT (ms) | tok/s  | Tokens in→out        | Reasoning | Notes`);
  console.log(`|-------------------|-----|-----------|--------|----------------------|-----------|------`);
  let totalPrompt = 0, totalCompletion = 0, totalReasoning = 0;
  for (const r of results) {
    const ok = r.ok ? '✅' : '❌';
    const ttft = r.ttftMs != null ? String(r.ttftMs).padStart(8) : '       —';
    const tps = r.tokPerSec != null ? r.tokPerSec.toFixed(1).padStart(6) : '     —';
    const tokens = r.promptTokens != null ? `${r.promptTokens}→${r.completionTokens}` : '—';
    const reasoning = r.reasoningTokens ? String(r.reasoningTokens) : '—';
    console.log(`| ${r.tool.padEnd(17)} | ${ok} | ${ttft}  | ${tps} | ${tokens.padEnd(20)} | ${reasoning.padStart(9)} | ${r.notes || ''}`);
    if (r.promptTokens) totalPrompt += r.promptTokens;
    if (r.completionTokens) totalCompletion += r.completionTokens;
    if (r.reasoningTokens) totalReasoning += r.reasoningTokens;
  }
  console.log(`\n   Tokens offloaded: ${(totalPrompt + totalCompletion).toLocaleString()} (prompt: ${totalPrompt.toLocaleString()}, completion: ${totalCompletion.toLocaleString()}, reasoning: ${totalReasoning.toLocaleString()})`);
  console.log(`   These tokens stayed on the local model and did not touch the Claude quota.\n`);

  process.exit(passed === results.length ? 0 : 1);
}

main().catch((err) => {
  console.error(`\n💥 Shakedown crashed: ${err.message}\n${err.stack || ''}`);
  process.exit(2);
});
