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
      'Send a message to the local LLM and get a response. Useful for offloading routine analysis to a local model and preserving Claude context.',
    inputSchema: {
      type: 'object' as const,
      properties: {
        message: { type: 'string', description: 'User message to send' },
        system: { type: 'string', description: 'Optional system prompt' },
        temperature: { type: 'number', description: 'Sampling temperature (0–2, default 0.3)' },
        max_tokens: { type: 'number', description: 'Max tokens in response (default 4096)' },
      },
      required: ['message'],
    },
  },
  {
    name: 'custom_prompt',
    description:
      'Run a structured prompt with system message, context, and instruction against the local LLM.',
    inputSchema: {
      type: 'object' as const,
      properties: {
        system: { type: 'string', description: 'System prompt / persona' },
        context: { type: 'string', description: 'Background context or data to analyse' },
        instruction: { type: 'string', description: 'What to do with the context' },
        temperature: { type: 'number', description: 'Sampling temperature (default 0.3)' },
        max_tokens: { type: 'number', description: 'Max tokens (default 4096)' },
      },
      required: ['instruction'],
    },
  },
  {
    name: 'list_models',
    description: 'List models currently loaded in LM Studio.',
    inputSchema: { type: 'object' as const, properties: {} },
  },
  {
    name: 'health_check',
    description: 'Check connectivity to the local LM Studio instance.',
    inputSchema: { type: 'object' as const, properties: {} },
  },
];

// ── MCP Server ───────────────────────────────────────────────────────

const server = new Server(
  { name: 'houtini-lm', version: '2.0.1' },
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
