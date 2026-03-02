#!/usr/bin/env node
/**
 * Houtini LM — MCP Server for Local LLMs via OpenAI-compatible API
 *
 * Connects to LM Studio (or any OpenAI-compatible endpoint) and exposes
 * chat, custom prompts, code tasks, and model discovery as MCP tools.
 */

import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
} from '@modelcontextprotocol/sdk/types.js';

const LM_BASE_URL = process.env.LM_STUDIO_URL || 'http://localhost:1234';
const LM_MODEL = process.env.LM_STUDIO_MODEL || '';
const LM_PASSWORD = process.env.LM_STUDIO_PASSWORD || '';
const DEFAULT_MAX_TOKENS = 2048;
const DEFAULT_TEMPERATURE = 0.3;
const CONNECT_TIMEOUT_MS = 5000;
const INFERENCE_CONNECT_TIMEOUT_MS = 30_000; // generous connect timeout for inference
const SOFT_TIMEOUT_MS = 55_000;              // return partial results before MCP SDK ~60s timeout
const READ_CHUNK_TIMEOUT_MS = 30_000;        // max wait for a single SSE chunk
const FALLBACK_CONTEXT_LENGTH = parseInt(process.env.LM_CONTEXT_WINDOW || '100000', 10);

// ── Session-level token accounting ───────────────────────────────────
// Tracks cumulative tokens offloaded to the local LLM across all calls
// in this session. Shown in every response footer so Claude can reason
// about cost savings and continue delegating strategically.

const session = {
  calls: 0,
  promptTokens: 0,
  completionTokens: 0,
};

function recordUsage(usage?: { prompt_tokens: number; completion_tokens: number }) {
  session.calls++;
  if (usage) {
    session.promptTokens += usage.prompt_tokens;
    session.completionTokens += usage.completion_tokens;
  }
}

function sessionSummary(): string {
  const total = session.promptTokens + session.completionTokens;
  if (session.calls === 0) return '';
  return `Session: ${total.toLocaleString()} tokens offloaded across ${session.calls} call${session.calls === 1 ? '' : 's'}`;
}

function apiHeaders(): Record<string, string> {
  const h: Record<string, string> = { 'Content-Type': 'application/json' };
  if (LM_PASSWORD) h['Authorization'] = `Bearer ${LM_PASSWORD}`;
  return h;
}

// ── OpenAI-compatible API helpers ────────────────────────────────────

interface ChatMessage {
  role: 'system' | 'user' | 'assistant';
  content: string;
}

interface StreamingResult {
  content: string;
  model: string;
  usage?: { prompt_tokens: number; completion_tokens: number; total_tokens: number };
  finishReason: string;
  truncated: boolean;
}

interface ModelInfo {
  id: string;
  context_length?: number;
  max_model_len?: number;
  owned_by?: string;
  [key: string]: unknown;
}

/**
 * Fetch with a connect timeout so Claude doesn't hang when the host is offline.
 */
async function fetchWithTimeout(
  url: string,
  options: RequestInit,
  timeoutMs: number = CONNECT_TIMEOUT_MS,
): Promise<Response> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    return await fetch(url, { ...options, signal: controller.signal });
  } finally {
    clearTimeout(timer);
  }
}

/**
 * Read from a stream with a per-chunk timeout.
 * Prevents hanging forever if the LLM stalls mid-generation.
 */
async function timedRead(
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
}

/**
 * Streaming chat completion with soft timeout.
 *
 * Uses SSE streaming (`stream: true`) so tokens arrive incrementally.
 * If we approach the MCP SDK's ~60s timeout (soft limit at 55s), we
 * return whatever content we have so far with `truncated: true`.
 * This means large code reviews return partial results instead of nothing.
 */
async function chatCompletionStreaming(
  messages: ChatMessage[],
  options: { temperature?: number; maxTokens?: number; model?: string } = {},
): Promise<StreamingResult> {
  const body: Record<string, unknown> = {
    messages,
    temperature: options.temperature ?? DEFAULT_TEMPERATURE,
    max_tokens: options.maxTokens ?? DEFAULT_MAX_TOKENS,
    stream: true,
  };
  if (options.model || LM_MODEL) {
    body.model = options.model || LM_MODEL;
  }

  const startTime = Date.now();

  const res = await fetchWithTimeout(
    `${LM_BASE_URL}/v1/chat/completions`,
    { method: 'POST', headers: apiHeaders(), body: JSON.stringify(body) },
    INFERENCE_CONNECT_TIMEOUT_MS,
  );

  if (!res.ok) {
    const text = await res.text().catch(() => '');
    throw new Error(`LM Studio API error ${res.status}: ${text}`);
  }

  if (!res.body) {
    throw new Error('Response body is null — streaming not supported by endpoint');
  }

  const reader = res.body.getReader();
  const decoder = new TextDecoder();
  let content = '';
  let model = '';
  let usage: StreamingResult['usage'];
  let finishReason = '';
  let truncated = false;
  let buffer = '';

  try {
    while (true) {
      // Check soft timeout before each read
      const elapsed = Date.now() - startTime;
      if (elapsed > SOFT_TIMEOUT_MS) {
        truncated = true;
        process.stderr.write(`[houtini-lm] Soft timeout at ${elapsed}ms, returning ${content.length} chars of partial content\n`);
        break;
      }

      // Read with per-chunk timeout (handles stalled generation)
      const remaining = SOFT_TIMEOUT_MS - elapsed;
      const chunkTimeout = Math.min(READ_CHUNK_TIMEOUT_MS, remaining);
      const result = await timedRead(reader, chunkTimeout);

      if (result === 'timeout') {
        truncated = true;
        process.stderr.write(`[houtini-lm] Chunk read timeout, returning ${content.length} chars of partial content\n`);
        break;
      }

      if (result.done) break;

      buffer += decoder.decode(result.value, { stream: true });

      // Parse SSE lines
      const lines = buffer.split('\n');
      buffer = lines.pop() || ''; // Keep incomplete line in buffer

      for (const line of lines) {
        const trimmed = line.trim();
        if (!trimmed || trimmed === 'data: [DONE]') continue;
        if (!trimmed.startsWith('data: ')) continue;

        try {
          const json = JSON.parse(trimmed.slice(6));
          if (json.model) model = json.model;

          const delta = json.choices?.[0]?.delta;
          if (delta?.content) content += delta.content;

          const reason = json.choices?.[0]?.finish_reason;
          if (reason) finishReason = reason;

          // Some endpoints include usage in the final streaming chunk
          if (json.usage) usage = json.usage;
        } catch {
          // Skip unparseable chunks (partial JSON, comments, etc.)
        }
      }
    }
  } finally {
    // Release the reader — don't await cancel() as it can hang
    reader.releaseLock();
  }

  return { content, model, usage, finishReason, truncated };
}

async function listModelsRaw(): Promise<ModelInfo[]> {
  const res = await fetchWithTimeout(
    `${LM_BASE_URL}/v1/models`,
    { headers: apiHeaders() },
  );
  if (!res.ok) throw new Error(`Failed to list models: ${res.status}`);
  const data = (await res.json()) as { data: ModelInfo[] };
  return data.data;
}

function getContextLength(model: ModelInfo): number {
  // LM Studio uses context_length, vLLM uses max_model_len, fall back to env/100k
  return model.context_length ?? model.max_model_len ?? FALLBACK_CONTEXT_LENGTH;
}

/**
 * Format a footer line for streaming results showing model, usage, and truncation status.
 */
function formatFooter(resp: StreamingResult, extra?: string): string {
  // Record usage for session tracking before formatting
  recordUsage(resp.usage);

  const parts: string[] = [];
  if (resp.model) parts.push(`Model: ${resp.model}`);
  if (resp.usage) parts.push(`This call: ${resp.usage.prompt_tokens}→${resp.usage.completion_tokens} tokens`);
  if (extra) parts.push(extra);
  if (resp.truncated) parts.push('⚠ TRUNCATED (soft timeout — partial result)');

  const sessionLine = sessionSummary();
  if (sessionLine) parts.push(sessionLine);

  return parts.length > 0 ? `\n\n---\n${parts.join(' | ')}` : '';
}

// ── MCP Tool definitions ─────────────────────────────────────────────

const TOOLS = [
  {
    name: 'chat',
    description:
      'Send a task to a local LLM running on a separate machine. This is a FREE, parallel worker — ' +
      'use it to offload bounded work while you continue doing other things. The local LLM runs independently ' +
      'and does not consume your tokens or rate limits.\n\n' +
      'PLANNING: When you start a large task (refactoring, migrations, test suites, documentation), ' +
      'break it into steps and identify which ones are bounded grunt work you can delegate here. ' +
      'The more you offload, the more tokens you save. The session footer tracks cumulative savings.\n\n' +
      'WHEN TO USE (delegate generously — it costs nothing):\n' +
      '• Explain or summarise code/docs you just read\n' +
      '• Generate boilerplate, test stubs, type definitions, mock data\n' +
      '• Answer factual questions about languages, frameworks, APIs\n' +
      '• Draft commit messages, PR descriptions, comments\n' +
      '• Translate or reformat content (JSON↔YAML, snake_case↔camelCase)\n' +
      '• Brainstorm approaches before you commit to one\n' +
      '• Any self-contained subtask that does not need tool access\n\n' +
      'PROMPT QUALITY (the local model is highly capable — results depend on your prompt):\n' +
      '(1) Always send COMPLETE code/context — never truncate, the local LLM cannot access files.\n' +
      '(2) Be explicit about output format ("respond as a JSON array", "return only the function").\n' +
      '(3) Set a specific persona in the system field — "Senior TypeScript dev" beats "helpful assistant".\n' +
      '(4) State constraints: "no preamble", "reference line numbers", "max 5 bullet points".\n' +
      '(5) For code generation, include the surrounding context (imports, types, function signatures).\n\n' +
      'QA: Always review the local LLM\'s output before using it. Verify correctness, check edge cases, ' +
      'and fix any issues. You are the architect — the local model is a fast drafter, not the final authority.\n\n' +
      'The local model, context window, and speed vary — call the discover tool to check what is loaded.',
    inputSchema: {
      type: 'object' as const,
      properties: {
        message: {
          type: 'string',
          description: 'The task. Be specific about expected output format. Include COMPLETE code/context — never truncate.',
        },
        system: {
          type: 'string',
          description: 'Persona for the local LLM. Be specific: "Senior TypeScript dev" not "helpful assistant".',
        },
        temperature: {
          type: 'number',
          description: '0.1 for factual/code, 0.3 for analysis (default), 0.7 for creative. Stay under 0.5 for code.',
        },
        max_tokens: {
          type: 'number',
          description: 'Max response tokens. Default 2048. Use higher for code generation, lower for quick answers.',
        },
      },
      required: ['message'],
    },
  },
  {
    name: 'custom_prompt',
    description:
      'Structured analysis via the local LLM with explicit system/context/instruction separation. ' +
      'This 3-part format prevents context bleed and gets the best results from local models.\n\n' +
      'USE THIS for complex tasks where prompt structure matters — it consistently outperforms ' +
      'stuffing everything into a single message. The separation helps the local model focus.\n\n' +
      'WHEN TO USE:\n' +
      '• Code review — paste full source, ask for bugs/improvements\n' +
      '• Comparison — paste two implementations, ask which is better and why\n' +
      '• Refactoring suggestions — paste code, ask for a cleaner version\n' +
      '• Content analysis — paste text, ask for structure/tone/issues\n' +
      '• Any task where separating context from instruction improves clarity\n\n' +
      'PROMPT STRUCTURE (each field has a job — keep them focused):\n' +
      '• System: persona + constraints, under 30 words. "Expert Python developer focused on performance and correctness."\n' +
      '• Context: COMPLETE data. Full source code, full logs, full text. NEVER truncate or summarise.\n' +
      '• Instruction: exactly what to produce, under 50 words. Specify format: "Return a JSON array of {line, issue, fix}."\n\n' +
      'QA: Review the output. The local model is a capable drafter — verify its analysis before acting on it.',
    inputSchema: {
      type: 'object' as const,
      properties: {
        system: {
          type: 'string',
          description: 'Persona. Be specific: "Expert Node.js developer focused on error handling and edge cases."',
        },
        context: {
          type: 'string',
          description: 'The COMPLETE data to analyse. Full source code, full logs, full text. NEVER truncate.',
        },
        instruction: {
          type: 'string',
          description: 'What to produce. Specify format: "List 3 bugs as bullet points" or "Return a JSON array of {line, issue, fix}".',
        },
        temperature: {
          type: 'number',
          description: '0.1 for bugs/review, 0.3 for analysis (default), 0.5 for suggestions.',
        },
        max_tokens: {
          type: 'number',
          description: 'Max response tokens. Default 2048.',
        },
      },
      required: ['instruction'],
    },
  },
  {
    name: 'code_task',
    description:
      'Send a code analysis task to the local LLM. Wraps the request with an optimised code-review system prompt.\n\n' +
      'This is the fastest way to offload code-specific work. Temperature is locked to 0.2 for ' +
      'focused, deterministic output. The system prompt is pre-configured for code review.\n\n' +
      'WHEN TO USE:\n' +
      '• Explain what a function/class does\n' +
      '• Find bugs or suggest improvements\n' +
      '• Generate unit tests or type definitions for existing code\n' +
      '• Add error handling, logging, or validation\n' +
      '• Convert between languages or patterns\n\n' +
      'GETTING BEST RESULTS:\n' +
      '• Provide COMPLETE source code — the local LLM cannot read files.\n' +
      '• Include imports and type definitions so the model has full context.\n' +
      '• Be specific in the task: "Write 3 Jest tests for the error paths in fetchUser" beats "Write tests".\n' +
      '• Set the language field — it shapes the system prompt and improves accuracy.\n\n' +
      'QA: Always verify generated code compiles, handles edge cases, and follows project conventions.',
    inputSchema: {
      type: 'object' as const,
      properties: {
        code: {
          type: 'string',
          description: 'COMPLETE source code. Never truncate. Include imports and full function bodies.',
        },
        task: {
          type: 'string',
          description: 'What to do: "Find bugs", "Explain this", "Add error handling to fetchData", "Write tests".',
        },
        language: {
          type: 'string',
          description: 'Programming language: "typescript", "python", "rust", etc.',
        },
        max_tokens: {
          type: 'number',
          description: 'Max response tokens. Default 2048.',
        },
      },
      required: ['code', 'task'],
    },
  },
  {
    name: 'discover',
    description:
      'Check whether the local LLM is online and what model is loaded. Returns model name, context window size, ' +
      'response latency, and cumulative session stats (tokens offloaded so far). ' +
      'Call this if you are unsure whether the local LLM is available before delegating work. ' +
      'Fast — typically responds in under 1 second, or returns an offline status within 5 seconds if the host is unreachable.',
    inputSchema: { type: 'object' as const, properties: {} },
  },
  {
    name: 'list_models',
    description:
      'List all models currently loaded in the local LLM server, with context window sizes. ' +
      'Use discover instead for a quick availability check.',
    inputSchema: { type: 'object' as const, properties: {} },
  },
];

// ── MCP Server ───────────────────────────────────────────────────────

const server = new Server(
  { name: 'houtini-lm', version: '2.4.0' },
  { capabilities: { tools: {} } },
);

server.setRequestHandler(ListToolsRequestSchema, async () => ({ tools: TOOLS }));

server.setRequestHandler(CallToolRequestSchema, async (request) => {
  const { name, arguments: args } = request.params;

  try {
    switch (name) {
      case 'chat': {
        const { message, system, temperature, max_tokens } = args as {
          message: string;
          system?: string;
          temperature?: number;
          max_tokens?: number;
        };
        const messages: ChatMessage[] = [];
        if (system) messages.push({ role: 'system', content: system });
        messages.push({ role: 'user', content: message });

        const resp = await chatCompletionStreaming(messages, {
          temperature,
          maxTokens: max_tokens,
        });

        const footer = formatFooter(resp);
        return { content: [{ type: 'text', text: resp.content + footer }] };
      }

      case 'custom_prompt': {
        const { system, context, instruction, temperature, max_tokens } = args as {
          system?: string;
          context?: string;
          instruction: string;
          temperature?: number;
          max_tokens?: number;
        };

        const messages: ChatMessage[] = [];
        if (system) messages.push({ role: 'system', content: system });

        let userContent = instruction;
        if (context) userContent = `Context:\n${context}\n\nInstruction:\n${instruction}`;
        messages.push({ role: 'user', content: userContent });

        const resp = await chatCompletionStreaming(messages, {
          temperature,
          maxTokens: max_tokens,
        });

        const footer = formatFooter(resp);
        return {
          content: [{ type: 'text', text: resp.content + footer }],
        };
      }

      case 'code_task': {
        const { code, task, language, max_tokens: codeMaxTokens } = args as {
          code: string;
          task: string;
          language?: string;
          max_tokens?: number;
        };

        const lang = language || 'unknown';
        const codeMessages: ChatMessage[] = [
          {
            role: 'system',
            content: `Expert ${lang} developer. Analyse the provided code and complete the task. Be specific — reference line numbers, function names, and concrete fixes. No preamble.`,
          },
          {
            role: 'user',
            content: `Task: ${task}\n\n\`\`\`${lang}\n${code}\n\`\`\``,
          },
        ];

        const codeResp = await chatCompletionStreaming(codeMessages, {
          temperature: 0.2,
          maxTokens: codeMaxTokens ?? DEFAULT_MAX_TOKENS,
        });

        const codeFooter = formatFooter(codeResp, lang);
        return { content: [{ type: 'text', text: codeResp.content + codeFooter }] };
      }

      case 'discover': {
        const start = Date.now();
        let models: ModelInfo[];
        try {
          models = await listModelsRaw();
        } catch (err) {
          const ms = Date.now() - start;
          const reason = err instanceof Error && err.name === 'AbortError'
            ? `Host unreachable (timed out after ${ms}ms)`
            : `Connection failed: ${err instanceof Error ? err.message : String(err)}`;
          return {
            content: [{
              type: 'text',
              text: `Status: OFFLINE\nEndpoint: ${LM_BASE_URL}\n${reason}\n\nThe local LLM is not available right now. Do not attempt to delegate tasks to it.`,
            }],
          };
        }
        const ms = Date.now() - start;

        if (models.length === 0) {
          return {
            content: [{
              type: 'text',
              text: `Status: ONLINE (no model loaded)\nEndpoint: ${LM_BASE_URL}\nLatency: ${ms}ms\n\nThe server is running but no model is loaded. Ask the user to load a model in LM Studio.`,
            }],
          };
        }

        const lines = models.map((m) => {
          const ctx = getContextLength(m);
          return `  • ${m.id} (context: ${ctx.toLocaleString()} tokens)`;
        });

        const primary = models[0];
        const ctx = getContextLength(primary);

        const sessionStats = session.calls > 0
          ? `\nSession stats: ${(session.promptTokens + session.completionTokens).toLocaleString()} tokens offloaded across ${session.calls} call${session.calls === 1 ? '' : 's'}`
          : '\nSession stats: no calls yet — delegate tasks to start saving tokens';

        return {
          content: [{
            type: 'text',
            text:
              `Status: ONLINE\n` +
              `Endpoint: ${LM_BASE_URL}\n` +
              `Latency: ${ms}ms\n` +
              `Model: ${primary.id}\n` +
              `Context window: ${ctx.toLocaleString()} tokens\n` +
              `\nLoaded models:\n${lines.join('\n')}` +
              `${sessionStats}\n\n` +
              `The local LLM is available. You can delegate tasks using chat, custom_prompt, or code_task.`,
          }],
        };
      }

      case 'list_models': {
        const models = await listModelsRaw();
        if (!models.length) {
          return { content: [{ type: 'text', text: 'No models currently loaded.' }] };
        }
        const lines = models.map((m) => {
          const ctx = getContextLength(m);
          return `  • ${m.id}${ctx ? ` (context: ${ctx.toLocaleString()} tokens)` : ''}`;
        });
        return {
          content: [{ type: 'text', text: `Loaded models:\n${lines.join('\n')}` }],
        };
      }

      default:
        throw new Error(`Unknown tool: ${name}`);
    }
  } catch (error) {
    return {
      content: [{ type: 'text', text: `Error: ${error instanceof Error ? error.message : String(error)}` }],
      isError: true,
    };
  }
});

async function main() {
  const transport = new StdioServerTransport();
  await server.connect(transport);
  process.stderr.write(`Houtini LM server running (${LM_BASE_URL})\n`);
}

main().catch((error) => {
  process.stderr.write(`Fatal error: ${error}\n`);
  process.exit(1);
});
