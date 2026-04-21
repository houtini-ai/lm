#!/usr/bin/env node
/**
 * End-to-end MCP smoke test — spawns the built server over stdio and
 * issues real tool calls. Used to validate provider-specific paths
 * (OpenRouter, LM Studio) exercise the expected branches.
 *
 * Usage:
 *   LM_STUDIO_URL=https://openrouter.ai/api \
 *   LM_PASSWORD=sk-or-v1-... \
 *   LM_STUDIO_MODEL=nvidia/nemotron-3-nano-30b-a3b:free \
 *   node test-mcp-e2e.mjs
 */

import { spawn } from 'node:child_process';
import { setTimeout as sleep } from 'node:timers/promises';

const server = spawn(process.execPath, ['dist/index.js'], {
  env: { ...process.env },
  stdio: ['pipe', 'pipe', 'pipe'],
});

let buf = '';
const pending = new Map();
let nextId = 1;

server.stdout.on('data', (chunk) => {
  buf += chunk.toString('utf8');
  let idx;
  while ((idx = buf.indexOf('\n')) >= 0) {
    const line = buf.slice(0, idx).trim();
    buf = buf.slice(idx + 1);
    if (!line) continue;
    try {
      const msg = JSON.parse(line);
      if (msg.id != null && pending.has(msg.id)) {
        const { resolve, reject } = pending.get(msg.id);
        pending.delete(msg.id);
        if (msg.error) reject(new Error(JSON.stringify(msg.error)));
        else resolve(msg.result);
      }
    } catch { /* ignore non-JSON log lines */ }
  }
});

server.stderr.on('data', (chunk) => {
  process.stderr.write(`[server] ${chunk}`);
});

async function rpc(method, params) {
  const id = nextId++;
  return new Promise((resolve, reject) => {
    pending.set(id, { resolve, reject });
    server.stdin.write(JSON.stringify({ jsonrpc: '2.0', id, method, params }) + '\n');
    setTimeout(() => {
      if (pending.has(id)) {
        pending.delete(id);
        reject(new Error(`RPC ${method} timed out`));
      }
    }, 120_000);
  });
}

function callTool(name, args) {
  return rpc('tools/call', { name, arguments: args });
}

let passed = 0, failed = 0;
async function test(name, fn) {
  try {
    await fn();
    console.log(`  PASS  ${name}`);
    passed++;
  } catch (e) {
    console.log(`  FAIL  ${name}`);
    console.log(`        ${e.message}`);
    failed++;
  }
}

try {
  await rpc('initialize', {
    protocolVersion: '2024-11-05',
    capabilities: {},
    clientInfo: { name: 'e2e-test', version: '0.1.0' },
  });
  await sleep(500);

  console.log('\n=== MCP E2E Smoke Test ===');
  console.log(`Target: ${process.env.LM_STUDIO_URL}`);
  console.log(`Model:  ${process.env.LM_STUDIO_MODEL || '(auto)'}\n`);

  await test('list_models returns non-empty set', async () => {
    const res = await callTool('list_models', {});
    const text = res.content?.[0]?.text || '';
    if (!text || text.length < 20) throw new Error(`Empty list_models: ${text.slice(0, 200)}`);
  });

  await test('chat: simple math', async () => {
    const res = await callTool('chat', {
      message: 'What is 17 * 23? Reply with just the number.',
      max_tokens: 256,
    });
    const text = res.content?.[0]?.text || '';
    if (!text.includes('391')) throw new Error(`Expected 391, got: ${text.slice(0, 300)}`);
  });

  await test('chat: system prompt respected', async () => {
    const res = await callTool('chat', {
      message: 'Describe JavaScript in one sentence.',
      system: 'You always answer like a pirate. Start every reply with "Arrr!".',
      max_tokens: 200,
    });
    const text = res.content?.[0]?.text || '';
    if (!/arr+!?/i.test(text)) throw new Error(`Not piratey: ${text.slice(0, 200)}`);
  });

  await test('chat: parallel requests (3)', async () => {
    const mkCall = (a, b) => callTool('chat', {
      message: `What is ${a}+${b}? Reply with just the number.`,
      max_tokens: 256,
    });
    const [r1, r2, r3] = await Promise.all([mkCall(10, 10), mkCall(20, 20), mkCall(30, 30)]);
    const t1 = r1.content?.[0]?.text || '';
    const t2 = r2.content?.[0]?.text || '';
    const t3 = r3.content?.[0]?.text || '';
    const hits = [t1.includes('20'), t2.includes('40'), t3.includes('60')].filter(Boolean).length;
    if (hits < 2) throw new Error(`Only ${hits}/3 parallel answers correct`);
  });

  console.log(`\n=== Results: ${passed} passed, ${failed} failed ===\n`);
} finally {
  server.kill();
}

process.exit(failed > 0 ? 1 : 0);
