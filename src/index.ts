#!/usr/bin/env node
/**
 * Houtini LM — MCP Server for Local LLMs via OpenAI-compatible API
 *
 * Connects to LM Studio (or any OpenAI-compatible endpoint) and exposes
 * chat, custom prompts, and model info as MCP tools.
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
const DEFAULT_MAX_TOKENS = 4096;
const DEFAULT_TEMPERATURE = 0.3;

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

interface ChatCompletionResponse {
  id: string;
  choices: Array<{
    message: { role: string; content: string };
    finish_reason: string;
  }>;
  model: string;
  usage?: { prompt_tokens: number; completion_tokens: number; total_tokens: number };
}

async function chatCompletion(
  messages: ChatMessage[],
  options: { temperature?: number; maxTokens?: number; model?: string } = {},
): Promise<ChatCompletionResponse> {
  const body: Record<string, unknown> = {
    messages,
    temperature: options.temperature ?? DEFAULT_TEMPERATURE,
    max_tokens: options.maxTokens ?? DEFAULT_MAX_TOKENS,
    stream: false,
  };
  if (options.model || LM_MODEL) {
    body.model = options.model || LM_MODEL;
  }

  const res = await fetch(`${LM_BASE_URL}/v1/chat/completions`, {
    method: 'POST',
    headers: apiHeaders(),
    body: JSON.stringify(body),
  });

  if (!res.ok) {
    const text = await res.text().catch(() => '');
    throw new Error(`LM Studio API error ${res.status}: ${text}`);
  }

  return res.json() as Promise<ChatCompletionResponse>;
}

async function listModels(): Promise<string[]> {
  const res = await fetch(`${LM_BASE_URL}/v1/models`, { headers: apiHeaders() });
  if (!res.ok) throw new Error(`Failed to list models: ${res.status}`);
  const data = (await res.json()) as { data: Array<{ id: string }> };
  return data.data.map((m) => m.id);
}

// ── MCP Tool definitions ─────────────────────────────────────────────

const TOOLS = [
  {
    name: 'chat',
    description:
      'Delegate a bounded task to the local LLM (Qwen3-Coder, ~3-4 tok/s). ' +
      'Best for: quick code explanation, pattern recognition, boilerplate generation, knowledge questions. ' +
      'Use when you can work in parallel — fire this off and continue your own work. ' +
      'RULES: (1) Always send COMPLETE code, never truncated — the local LLM WILL hallucinate details for missing code. ' +
      '(2) Set max_tokens to match expected output: 150 for quick answers (~45s), 300 for explanations (~100s), 500 for code generation (~170s). ' +
      '(3) Be explicit about output format in your message ("respond in 3 bullets", "return only the function"). ' +
      'DO NOT use for: multi-step reasoning, creative writing, tasks needing >500 token output, or anything requiring tool use (use lm-taskrunner for tool-augmented tasks via mcpo).',
    inputSchema: {
      type: 'object' as const,
      properties: {
        message: { type: 'string', description: 'The task. Be specific about expected output format and length. Include COMPLETE code — never truncate.' },
        system: { type: 'string', description: 'Persona for the local LLM. Be specific: "Senior TypeScript dev" not "helpful assistant". Short personas (under 30 words) get best results.' },
        temperature: { type: 'number', description: '0.1 for factual/code tasks, 0.3 for analysis (default), 0.7 for creative suggestions. Stay under 0.5 for code.' },
        max_tokens: { type: 'number', description: 'Cap this to match expected output. 150=quick answer, 300=explanation, 500=code generation. Lower = faster. Default 4096 is almost always too high.' },
      },
      required: ['message'],
    },
  },
  {
    name: 'custom_prompt',
    description:
      'Structured analysis on the local LLM with explicit system/context/instruction separation. ' +
      'This 3-part format gets the best results from local models — the separation prevents context bleed. ' +
      'System sets persona (be specific: "Senior TypeScript dev reviewing for security bugs"). ' +
      'Context provides COMPLETE data (full source file, full error log — never truncated). ' +
      'Instruction states exactly what to produce (under 50 words for best results). ' +
      'Best for: code review, comparison, refactoring suggestions, structured analysis. ' +
      'Expect 30-180s response time depending on max_tokens.',
    inputSchema: {
      type: 'object' as const,
      properties: {
        system: { type: 'string', description: 'Persona. Be specific and under 30 words. Example: "Expert Node.js developer focused on error handling and edge cases."' },
        context: { type: 'string', description: 'The COMPLETE data to analyse. Full source code, full logs, full text. NEVER truncate — the local LLM fills gaps with plausible hallucinations.' },
        instruction: { type: 'string', description: 'What to produce. Under 50 words. Specify format: "List 3 bugs as bullet points" or "Return a JSON array of {line, issue, fix}".' },
        temperature: { type: 'number', description: '0.1 for bugs/review, 0.3 for analysis (default), 0.5 for suggestions.' },
        max_tokens: { type: 'number', description: 'Match to expected output. 200 for bullets, 400 for detailed review, 600 for code generation.' },
      },
      required: ['instruction'],
    },
  },
  {
    name: 'code_task',
    description:
      'Purpose-built for code analysis tasks. Wraps the local LLM with an optimised code-review system prompt. ' +
      'Provide COMPLETE source code and a specific task — returns analysis in ~30-180s. ' +
      'Ideal for parallel execution: delegate to local LLM while you handle other work. ' +
      'The local LLM excels at: explaining code, finding common bugs, suggesting improvements, comparing patterns, generating boilerplate. ' +
      'It struggles with: subtle/adversarial bugs, multi-file reasoning, design tasks requiring integration. ' +
      'Output capped at 500 tokens by default (override with max_tokens).',
    inputSchema: {
      type: 'object' as const,
      properties: {
        code: { type: 'string', description: 'COMPLETE source code. Never truncate. Include imports and full function bodies.' },
        task: { type: 'string', description: 'What to do. Be specific and concise: "Find bugs", "Explain this function", "Add error handling to fetchData", "Compare these two approaches".' },
        language: { type: 'string', description: 'Programming language for context: "typescript", "python", "rust", etc.' },
        max_tokens: { type: 'number', description: 'Expected output size. Default 500. Use 200 for quick answers, 800 for code generation.' },
      },
      required: ['code', 'task'],
    },
  },
  {
    name: 'list_models',
    description: 'List models currently loaded in LM Studio. Use to verify which model will handle delegated tasks.',
    inputSchema: { type: 'object' as const, properties: {} },
  },
  {
    name: 'health_check',
    description: 'Check connectivity and latency to the local LM Studio instance. Run before delegating time-sensitive tasks.',
    inputSchema: { type: 'object' as const, properties: {} },
  },
];

// ── MCP Server ───────────────────────────────────────────────────────

const server = new Server(
  { name: 'houtini-lm', version: '2.1.0' },
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

        const resp = await chatCompletion(messages, {
          temperature,
          maxTokens: max_tokens,
        });

        const reply = resp.choices[0]?.message?.content ?? '';
        const usage = resp.usage
          ? `\n\n---\nModel: ${resp.model} | Tokens: ${resp.usage.prompt_tokens}→${resp.usage.completion_tokens}`
          : '';

        return { content: [{ type: 'text', text: reply + usage }] };
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

        const resp = await chatCompletion(messages, {
          temperature,
          maxTokens: max_tokens,
        });

        return {
          content: [{ type: 'text', text: resp.choices[0]?.message?.content ?? '' }],
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

        const codeResp = await chatCompletion(codeMessages, {
          temperature: 0.2,
          maxTokens: codeMaxTokens ?? 500,
        });

        const codeReply = codeResp.choices[0]?.message?.content ?? '';
        const codeUsage = codeResp.usage
          ? `\n\n---\nModel: ${codeResp.model} | Tokens: ${codeResp.usage.prompt_tokens}→${codeResp.usage.completion_tokens} | ${lang}`
          : '';

        return { content: [{ type: 'text', text: codeReply + codeUsage }] };
      }

      case 'list_models': {
        const models = await listModels();
        return {
          content: [
            {
              type: 'text',
              text: models.length
                ? `Loaded models:\n${models.map((m) => `  • ${m}`).join('\n')}`
                : 'No models currently loaded.',
            },
          ],
        };
      }

      case 'health_check': {
        const start = Date.now();
        const models = await listModels();
        const ms = Date.now() - start;
        return {
          content: [
            {
              type: 'text',
              text: `Connected to ${LM_BASE_URL} (${ms}ms)\nAuth: ${LM_PASSWORD ? 'enabled' : 'none'}\nModels loaded: ${models.length}${models.length ? '\n' + models.join(', ') : ''}`,
            },
          ],
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
