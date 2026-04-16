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
  ListResourcesRequestSchema,
  ReadResourceRequestSchema,
} from '@modelcontextprotocol/sdk/types.js';
import {
  profileModelsAtStartup,
  getCachedProfile,
  toModelProfile as cachedToProfile,
  getHFEnrichmentLine,
  getPromptHints,
  getThinkingSupport,
  type PromptHints,
} from './model-cache.js';
import { readFile } from 'node:fs/promises';
import { isAbsolute, basename } from 'node:path';

const LM_BASE_URL = process.env.LM_STUDIO_URL || 'http://localhost:1234';
const LM_MODEL = process.env.LM_STUDIO_MODEL || '';
const LM_PASSWORD = process.env.LM_STUDIO_PASSWORD || '';
const DEFAULT_MAX_TOKENS = 16384;             // fallback when model context is unknown — overridden by dynamic calculation below
const DEFAULT_TEMPERATURE = 0.3;
const CONNECT_TIMEOUT_MS = 5000;
const INFERENCE_CONNECT_TIMEOUT_MS = 30_000; // generous connect timeout for inference
const SOFT_TIMEOUT_MS = 300_000;             // 5 min — progress notifications reset MCP client timeout, so this is a safety net not the primary limit
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
  /** Per-model performance tracking for routing insights */
  modelStats: new Map<string, { calls: number; perfCalls: number; totalTtftMs: number; totalTokPerSec: number }>(),
};

function recordUsage(resp: StreamingResult) {
  session.calls++;
  if (resp.usage) {
    session.promptTokens += resp.usage.prompt_tokens;
    session.completionTokens += resp.usage.completion_tokens;
  } else if (resp.content.length > 0) {
    // Estimate when usage is missing (truncated responses)
    session.completionTokens += Math.ceil(resp.content.length / 4);
  }
  // Track per-model perf stats
  if (resp.model) {
    const existing = session.modelStats.get(resp.model) || { calls: 0, perfCalls: 0, totalTtftMs: 0, totalTokPerSec: 0 };
    existing.calls++;
    if (resp.ttftMs) existing.totalTtftMs += resp.ttftMs;
    const tokPerSec = resp.usage && resp.generationMs > 50
      ? (resp.usage.completion_tokens / (resp.generationMs / 1000))
      : 0;
    if (tokPerSec > 0) {
      existing.perfCalls++;
      existing.totalTokPerSec += tokPerSec;
    }
    session.modelStats.set(resp.model, existing);
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

// ── Request semaphore ────────────────────────────────────────────────
// Most local LLM servers run a single model and queue parallel requests,
// which stacks timeouts and wastes the 55s budget. This semaphore ensures
// only one inference call runs at a time; others wait in line.

let inferenceLock: Promise<void> = Promise.resolve();

function withInferenceLock<T>(fn: () => Promise<T>): Promise<T> {
  let release: () => void;
  const next = new Promise<void>((resolve) => { release = resolve; });
  const wait = inferenceLock;
  inferenceLock = next;
  return wait.then(fn).finally(() => release!());
}

// ── OpenAI-compatible API helpers ────────────────────────────────────

interface ChatMessage {
  role: 'system' | 'user' | 'assistant';
  content: string;
}

interface StreamingResult {
  content: string;
  /** Raw content before think-block stripping (for quality assessment) */
  rawContent: string;
  model: string;
  usage?: { prompt_tokens: number; completion_tokens: number; total_tokens: number };
  finishReason: string;
  truncated: boolean;
  /** Time to first token in milliseconds */
  ttftMs?: number;
  /** Total generation time in milliseconds */
  generationMs: number;
  /** True when think-block stripping left nothing and we fell back to raw content */
  thinkStripFallback?: boolean;
}

/** OpenAI-compatible response_format for structured output */
interface ResponseFormat {
  type: 'json_schema' | 'json_object' | 'text';
  json_schema?: {
    name: string;
    strict?: boolean | string;
    schema: Record<string, unknown>;
  };
}

interface ModelInfo {
  id: string;
  object?: string;
  type?: string;              // "llm" | "vlm" | "embeddings"
  publisher?: string;          // e.g. "nvidia", "qwen", "ibm"
  arch?: string;               // e.g. "nemotron_h_moe", "qwen3moe", "llama"
  compatibility_type?: string; // "gguf" | "mlx"
  quantization?: string;       // e.g. "Q4_K_M", "BF16", "MXFP4"
  state?: string;              // "loaded" | "not-loaded"
  max_context_length?: number; // model's maximum context (v0 API)
  loaded_context_length?: number; // actual context configured when loaded
  capabilities?: string[];     // e.g. ["tool_use"]
  context_length?: number;     // v1 API fallback
  max_model_len?: number;      // vLLM fallback
  owned_by?: string;
  [key: string]: unknown;
}

// ── Model knowledge base ─────────────────────────────────────────────
// Maps known model families (matched by ID or architecture) to human-readable
// descriptions and capability profiles. This lets houtini-lm tell Claude what
// each model is good at, so it can make informed delegation decisions.

interface ModelProfile {
  family: string;
  description: string;
  strengths: string[];
  weaknesses: string[];
  bestFor: string[];
  size?: string; // e.g. "3B", "70B" — only if consistently one size
}

const MODEL_PROFILES: { pattern: RegExp; profile: ModelProfile }[] = [
  {
    pattern: /nemotron|nemotron_h_moe/i,
    profile: {
      family: 'NVIDIA Nemotron',
      description: 'NVIDIA\'s compact reasoning model optimised for accurate, structured responses. Strong at step-by-step logic and instruction following.',
      strengths: ['logical reasoning', 'math', 'step-by-step problem solving', 'code review', 'structured output'],
      weaknesses: ['creative writing', 'constrained generation', 'factual knowledge on niche topics'],
      bestFor: ['analysis tasks', 'code bug-finding', 'math/science questions', 'data transformation'],
    },
  },
  {
    pattern: /granite|granitehybrid/i,
    profile: {
      family: 'IBM Granite',
      description: 'IBM\'s enterprise-focused model family. Compact and efficient, designed for business and code tasks with strong instruction following.',
      strengths: ['code generation', 'instruction following', 'enterprise tasks', 'efficiency'],
      weaknesses: ['creative tasks', 'long-form generation'],
      bestFor: ['boilerplate generation', 'code explanation', 'structured Q&A'],
    },
  },
  {
    pattern: /qwen3-coder|qwen3.*coder/i,
    profile: {
      family: 'Qwen3 Coder',
      description: 'Alibaba\'s code-specialised model with agentic capabilities. Excellent at code generation, review, and multi-step coding tasks.',
      strengths: ['code generation', 'code review', 'debugging', 'test writing', 'refactoring', 'multi-step reasoning'],
      weaknesses: ['non-code creative tasks'],
      bestFor: ['code generation', 'code review', 'test stubs', 'type definitions', 'refactoring'],
    },
  },
  {
    pattern: /qwen3-vl|qwen.*vl/i,
    profile: {
      family: 'Qwen3 Vision-Language',
      description: 'Alibaba\'s multimodal model handling both text and image inputs. Can analyse screenshots, diagrams, and visual content.',
      strengths: ['image understanding', 'visual Q&A', 'diagram analysis', 'OCR'],
      weaknesses: ['pure text tasks (use a text-only model instead)'],
      bestFor: ['screenshot analysis', 'UI review', 'diagram interpretation'],
    },
  },
  {
    pattern: /qwen3(?!.*coder)(?!.*vl)/i,
    profile: {
      family: 'Qwen3',
      description: 'Alibaba\'s general-purpose model with strong multilingual and reasoning capabilities. Good all-rounder.',
      strengths: ['general reasoning', 'multilingual', 'code', 'instruction following'],
      weaknesses: ['specialised code tasks (use Qwen3 Coder instead)'],
      bestFor: ['general Q&A', 'translation', 'summarisation', 'brainstorming'],
    },
  },
  {
    pattern: /llama[- ]?3/i,
    profile: {
      family: 'Meta LLaMA 3',
      description: 'Meta\'s open-weight general-purpose model. Strong baseline across tasks with large community fine-tune ecosystem.',
      strengths: ['general reasoning', 'code', 'instruction following', 'broad knowledge'],
      weaknesses: ['specialised tasks where fine-tuned models excel'],
      bestFor: ['general delegation', 'drafting', 'code review', 'Q&A'],
    },
  },
  {
    pattern: /minimax[- ]?m2/i,
    profile: {
      family: 'MiniMax M2',
      description: 'MiniMax\'s large MoE model with strong long-context and reasoning capabilities.',
      strengths: ['long context', 'reasoning', 'creative writing', 'multilingual'],
      weaknesses: ['may be slower due to model size'],
      bestFor: ['long document analysis', 'creative tasks', 'complex reasoning'],
    },
  },
  {
    pattern: /kimi[- ]?k2/i,
    profile: {
      family: 'Kimi K2',
      description: 'Moonshot AI\'s large MoE model with strong agentic and tool-use capabilities.',
      strengths: ['agentic tasks', 'tool use', 'code', 'reasoning', 'long context'],
      weaknesses: ['may be slower due to model size'],
      bestFor: ['complex multi-step tasks', 'code generation', 'reasoning chains'],
    },
  },
  {
    pattern: /gpt-oss/i,
    profile: {
      family: 'OpenAI GPT-OSS',
      description: 'OpenAI\'s open-source model release. General-purpose with strong instruction following.',
      strengths: ['instruction following', 'general reasoning', 'code'],
      weaknesses: ['less tested in open ecosystem than LLaMA/Qwen'],
      bestFor: ['general delegation', 'code tasks', 'Q&A'],
    },
  },
  {
    pattern: /glm[- ]?4/i,
    profile: {
      family: 'GLM-4',
      description: 'Zhipu AI\'s open-weight MoE model. Fast inference with strong general reasoning, multilingual support, and tool-use capabilities. Uses chain-of-thought reasoning internally. MIT licensed.',
      strengths: ['fast inference', 'general reasoning', 'tool use', 'multilingual', 'code', 'instruction following', 'chain-of-thought'],
      weaknesses: ['always emits internal reasoning (stripped automatically)', 'less tested in English-only benchmarks than LLaMA/Qwen'],
      bestFor: ['general delegation', 'fast drafting', 'code tasks', 'structured output', 'Q&A'],
    },
  },
  {
    pattern: /nomic.*embed|embed.*nomic/i,
    profile: {
      family: 'Nomic Embed',
      description: 'Text embedding model for semantic search and similarity. Not a chat model — produces vector embeddings.',
      strengths: ['text embeddings', 'semantic search', 'clustering'],
      weaknesses: ['cannot chat or generate text'],
      bestFor: ['RAG pipelines', 'semantic similarity', 'document search'],
    },
  },
  {
    pattern: /abliterated/i,
    profile: {
      family: 'Abliterated (uncensored)',
      description: 'Community fine-tune with safety guardrails removed. More permissive but may produce lower-quality or unreliable output.',
      strengths: ['fewer refusals', 'unconstrained generation'],
      weaknesses: ['may hallucinate more', 'no safety filtering', 'less tested'],
      bestFor: ['tasks where the base model refuses unnecessarily'],
    },
  },
];

/**
 * Match a model to its known profile.
 * Priority: 1) static MODEL_PROFILES (curated), 2) SQLite cache (auto-generated from HF)
 */
function getModelProfile(model: ModelInfo): ModelProfile | undefined {
  // Try static profiles first (curated, most reliable)
  for (const { pattern, profile } of MODEL_PROFILES) {
    if (pattern.test(model.id)) return profile;
  }
  if (model.arch) {
    for (const { pattern, profile } of MODEL_PROFILES) {
      if (pattern.test(model.arch)) return profile;
    }
  }
  return undefined;
}

/**
 * Async version that also checks SQLite cache for auto-generated profiles.
 * Use this when you need the most complete profile available.
 */
async function getModelProfileAsync(model: ModelInfo): Promise<ModelProfile | undefined> {
  // Static profiles take priority
  const staticProfile = getModelProfile(model);
  if (staticProfile) return staticProfile;

  // Check SQLite cache for auto-generated profile
  try {
    const cached = await getCachedProfile(model.id);
    if (cached) {
      const profile = cachedToProfile(cached);
      if (profile) return profile;
    }
  } catch {
    // Cache lookup failed — fall through
  }

  return undefined;
}

/**
 * Format a single model's full metadata for display.
 * Async because it may fetch HuggingFace enrichment data.
 */
async function formatModelDetail(model: ModelInfo, enrichWithHF: boolean = false): Promise<string> {
  const ctx = getContextLength(model);
  const maxCtx = getMaxContextLength(model);
  // Use async profile lookup (checks static + SQLite cache)
  const profile = await getModelProfileAsync(model);
  const parts: string[] = [];

  // Header line
  parts.push(`  ${model.state === 'loaded' ? '●' : '○'} ${model.id}`);

  // Metadata line
  const meta: string[] = [];
  if (model.type) meta.push(`type: ${model.type}`);
  if (model.arch) meta.push(`arch: ${model.arch}`);
  if (model.quantization) meta.push(`quant: ${model.quantization}`);
  if (model.compatibility_type) meta.push(`format: ${model.compatibility_type}`);
  // Show loaded context vs max context when both are available and different
  if (model.loaded_context_length && maxCtx && model.loaded_context_length !== maxCtx) {
    meta.push(`context: ${model.loaded_context_length.toLocaleString()} (max ${maxCtx.toLocaleString()})`);
  } else if (ctx) {
    meta.push(`context: ${ctx.toLocaleString()}`);
  }
  if (model.publisher) meta.push(`by: ${model.publisher}`);
  if (meta.length > 0) parts.push(`    ${meta.join(' · ')}`);

  // Capabilities
  if (model.capabilities && model.capabilities.length > 0) {
    parts.push(`    Capabilities: ${model.capabilities.join(', ')}`);
  }

  // Profile info (static or auto-generated from SQLite cache)
  if (profile) {
    parts.push(`    ${profile.family}: ${profile.description}`);
    parts.push(`    Best for: ${profile.bestFor.join(', ')}`);
  }

  // HuggingFace enrichment line from SQLite cache
  if (enrichWithHF) {
    try {
      const hfLine = await getHFEnrichmentLine(model.id);
      if (hfLine) parts.push(hfLine);
    } catch {
      // HF enrichment is best-effort — never block on failure
    }
  }

  return parts.join('\n');
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
  options: { temperature?: number; maxTokens?: number; model?: string; responseFormat?: ResponseFormat; progressToken?: string | number } = {},
): Promise<StreamingResult> {
  return withInferenceLock(() => chatCompletionStreamingInner(messages, options));
}

/** Get the first loaded model's info for context-aware defaults. */
async function getActiveModel(): Promise<ModelInfo | null> {
  try {
    const models = await listModelsRaw();
    return models.find((m: ModelInfo) => m.state === 'loaded') ?? models[0] ?? null;
  } catch { return null; }
}

async function chatCompletionStreamingInner(
  messages: ChatMessage[],
  options: { temperature?: number; maxTokens?: number; model?: string; responseFormat?: ResponseFormat; progressToken?: string | number } = {},
): Promise<StreamingResult> {
  // Derive max_tokens from the model's actual context window when not explicitly set.
  // Uses 25% of context as a generous output budget (e.g. 262K context → 65K output).
  let effectiveMaxTokens = options.maxTokens ?? DEFAULT_MAX_TOKENS;
  if (!options.maxTokens) {
    const activeModel = await getActiveModel();
    if (activeModel) {
      const ctx = getContextLength(activeModel);
      effectiveMaxTokens = Math.floor(ctx * 0.25);
    }
  }

  const body: Record<string, unknown> = {
    messages,
    temperature: options.temperature ?? DEFAULT_TEMPERATURE,
    max_tokens: effectiveMaxTokens,
    stream: true,
    stream_options: { include_usage: true },
  };
  if (options.model || LM_MODEL) {
    body.model = options.model || LM_MODEL;
  }
  if (options.responseFormat) {
    body.response_format = options.responseFormat;
  }

  // Handle thinking/reasoning models.
  // Some models (Gemma 4, Qwen3, DeepSeek) have extended thinking that consumes
  // part of the max_tokens budget for invisible reasoning before producing content.
  // Strategy: try to disable thinking via enable_thinking=false, BUT also inflate
  // max_tokens as a safety net since some models (Gemma 4) hardcode thinking=true
  // in their Jinja template and ignore the API parameter.
  const modelId = (options.model || LM_MODEL || '').toString();
  if (modelId) {
    const thinking = await getThinkingSupport(modelId);
    if (thinking?.supportsThinkingToggle) {
      body.enable_thinking = false;
      // Safety net: inflate max_tokens to account for reasoning budget.
      // Gemma 4 ignores enable_thinking=false (hardcoded in template),
      // so the model will think regardless. Without inflation, reasoning
      // consumes all tokens and content comes back empty.
      const requestedTokens = (options.maxTokens ?? DEFAULT_MAX_TOKENS);
      body.max_tokens = Math.max(requestedTokens * 4, requestedTokens + 2000);
      process.stderr.write(`[houtini-lm] Thinking model ${modelId}: enable_thinking=false, max_tokens inflated ${requestedTokens} → ${body.max_tokens}\n`);
    }
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
  let chunkCount = 0;
  let model = '';
  let usage: StreamingResult['usage'];
  let finishReason = '';
  let truncated = false;
  let buffer = '';
  let ttftMs: number | undefined;

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

          // Track reasoning/thinking tokens — models like Gemma 4, Qwen3, DeepSeek
          // emit reasoning_content during their thinking phase before producing
          // visible content. We must send progress notifications during this phase
          // to prevent MCP client timeout.
          if (delta?.reasoning_content) {
            chunkCount++;
            if (options.progressToken !== undefined) {
              server.notification({
                method: 'notifications/progress',
                params: {
                  progressToken: options.progressToken,
                  progress: chunkCount,
                  message: `Thinking... (${chunkCount} chunks)`,
                },
              }).catch(() => { /* best-effort */ });
            }
          }

          if (delta?.content) {
            if (ttftMs === undefined) ttftMs = Date.now() - startTime;
            content += delta.content;
            chunkCount++;
            // Send progress notification to reset MCP client timeout.
            // Each notification resets the 60s clock, giving slow models
            // unlimited time as long as they're actively generating.
            if (options.progressToken !== undefined) {
              server.notification({
                method: 'notifications/progress',
                params: {
                  progressToken: options.progressToken,
                  progress: chunkCount,
                  message: `Streaming... ${content.length} chars`,
                },
              }).catch(() => { /* best-effort — don't break streaming */ });
            }
          }

          const reason = json.choices?.[0]?.finish_reason;
          if (reason) finishReason = reason;

          // Some endpoints include usage in the final streaming chunk
          if (json.usage) usage = json.usage;
        } catch {
          // Skip unparseable chunks (partial JSON, comments, etc.)
        }
      }
    }

    // Flush remaining buffer — the usage chunk often arrives in the final SSE
    // message and may not have a trailing newline, leaving it stranded in buffer.
    if (buffer.trim()) {
      const trimmed = buffer.trim();
      if (trimmed.startsWith('data: ') && trimmed !== 'data: [DONE]') {
        try {
          const json = JSON.parse(trimmed.slice(6));
          if (json.model) model = json.model;
          const delta = json.choices?.[0]?.delta;
          if (delta?.content) {
            if (ttftMs === undefined) ttftMs = Date.now() - startTime;
            content += delta.content;
          }
          const reason = json.choices?.[0]?.finish_reason;
          if (reason) finishReason = reason;
          if (json.usage) usage = json.usage;
        } catch (e) {
          // Incomplete JSON in final buffer — log for diagnostics
          process.stderr.write(`[houtini-lm] Unflushed buffer parse failed (${buffer.length} bytes): ${e}\n`);
        }
      }
    }
  } finally {
    // Release the reader — don't await cancel() as it can hang
    reader.releaseLock();
  }

  const generationMs = Date.now() - startTime;

  // Strip <think>...</think> reasoning blocks from models that always emit them
  // (e.g. GLM Flash, Nemotron). Claude doesn't need the model's internal reasoning.
  // Handle both closed blocks and unclosed ones (model ran out of tokens mid-think,
  // or grammar-constrained output forced content before the closing tag).
  let cleanContent = content.replace(/<think>[\s\S]*?<\/think>\s*/g, '');  // closed blocks
  cleanContent = cleanContent.replace(/^<think>\s*/, '');                   // orphaned opening tag
  cleanContent = cleanContent.trim();

  // Safety net on top of the thinking-model max_tokens inflation: some MLX/GGUF
  // quants still exhaust their budget inside an unclosed <think> block despite
  // `enable_thinking:false` and the 4× inflation. If stripping leaves nothing but
  // raw output exists, return the raw reasoning so the caller sees *something*
  // rather than an empty body + lone footer (issue #6).
  let thinkStripFallback = false;
  if (!cleanContent && content.trim()) {
    thinkStripFallback = true;
    cleanContent = content.trim();
  }

  return { content: cleanContent, rawContent: content, model, usage, finishReason, truncated, ttftMs, generationMs, thinkStripFallback };
}

/**
 * Fetch models from LM Studio's native v0 API first (richer metadata),
 * falling back to the OpenAI-compatible v1 endpoint for non-LM-Studio hosts.
 */
async function listModelsRaw(): Promise<ModelInfo[]> {
  // Try v0 API first — returns type, arch, publisher, quantization, state
  try {
    const v0 = await fetchWithTimeout(
      `${LM_BASE_URL}/api/v0/models`,
      { headers: apiHeaders() },
    );
    if (v0.ok) {
      const data = (await v0.json()) as { data: ModelInfo[] };
      return data.data;
    }
  } catch {
    // v0 not available — fall through to v1
  }

  // Fallback: OpenAI-compatible v1 endpoint (works with Ollama, vLLM, llama.cpp)
  const res = await fetchWithTimeout(
    `${LM_BASE_URL}/v1/models`,
    { headers: apiHeaders() },
  );
  if (!res.ok) throw new Error(`Failed to list models: ${res.status}`);
  const data = (await res.json()) as { data: ModelInfo[] };
  return data.data;
}

function getContextLength(model: ModelInfo): number {
  // Prefer loaded_context_length (actual configured context) over max_context_length (theoretical max)
  // v0 API: loaded_context_length / max_context_length, v1: context_length, vLLM: max_model_len
  return model.loaded_context_length ?? model.max_context_length ?? model.context_length ?? model.max_model_len ?? FALLBACK_CONTEXT_LENGTH;
}

function getMaxContextLength(model: ModelInfo): number | undefined {
  return model.max_context_length;
}

// ── Model routing ─────────────────────────────────────────────────────
// Picks the best loaded model for a given task type.
// If only one model is loaded, uses it but may suggest a better one.
// If multiple are loaded, routes to the best match.

type TaskType = 'code' | 'chat' | 'analysis' | 'embedding';

interface RoutingDecision {
  modelId: string;
  hints: PromptHints;
  suggestion?: string;  // info about routing decision
}

async function routeToModel(taskType: TaskType): Promise<RoutingDecision> {
  let models: ModelInfo[];
  try {
    models = await listModelsRaw();
  } catch {
    // Can't reach server — fall back to default
    const hints = getPromptHints(LM_MODEL);
    return { modelId: LM_MODEL || '', hints };
  }

  const loaded = models.filter((m) => m.state === 'loaded' || !m.state);
  const available = models.filter((m) => m.state === 'not-loaded');

  if (loaded.length === 0) {
    const hints = getPromptHints(LM_MODEL);
    return { modelId: LM_MODEL || '', hints };
  }

  // Score each loaded model for the requested task type
  let bestModel = loaded[0];
  let bestScore = -1;

  for (const model of loaded) {
    const hints = getPromptHints(model.id, model.arch);
    // Primary: is this task type in the model's best types?
    let score = (hints.bestTaskTypes ?? []).includes(taskType) ? 10 : 0;
    // Bonus: code-specialised models get extra points for code tasks
    const profile = getModelProfile(model);
    if (taskType === 'code' && profile?.family.toLowerCase().includes('coder')) score += 5;
    // Bonus: larger context for analysis tasks
    if (taskType === 'analysis') {
      const ctx = getContextLength(model);
      if (ctx && ctx > 100000) score += 2;
    }
    if (score > bestScore) {
      bestScore = score;
      bestModel = model;
    }
  }

  const hints = getPromptHints(bestModel.id, bestModel.arch);
  const result: RoutingDecision = { modelId: bestModel.id, hints };

  // If the best loaded model isn't ideal for this task, suggest a better available one.
  // We don't JIT-load because model loading takes minutes and the MCP SDK has a ~60s
  // hard timeout. Instead, suggest the user loads the better model in LM Studio.
  if (!(hints.bestTaskTypes ?? []).includes(taskType)) {
    const better = available.find((m) => {
      const mHints = getPromptHints(m.id, m.arch);
      return (mHints.bestTaskTypes ?? []).includes(taskType);
    });
    if (better) {
      const label = taskType === 'code' ? 'code tasks'
        : taskType === 'analysis' ? 'analysis'
        : taskType === 'embedding' ? 'embeddings'
        : 'this kind of task';
      result.suggestion = `💡 ${better.id} is downloaded and better suited for ${label} — ask the user to load it in LM Studio.`;
    }
  }

  return result;
}

// ── Quality metadata ─────────────────────────────────────────────────
// Provides structured quality signals in every response so Claude (or any
// orchestrator) can make informed trust decisions about the local LLM output.
// Addresses: GitHub issue #3 (automated quality checks), dev.to feedback
// on leaked think-blocks and token offload metrics as routing feedback.

interface QualitySignal {
  truncated: boolean;
  finishReason: string;
  thinkBlocksStripped: boolean;
  thinkStripFallback: boolean;  // strip emptied content; returning raw as fallback
  estimatedTokens: boolean;   // true when usage was missing and we estimated
  contentLength: number;
  generationMs: number;
  tokPerSec: number | null;
}

function assessQuality(resp: StreamingResult, rawContent: string): QualitySignal {
  const hadThinkBlocks = /<think>/.test(rawContent);
  const estimated = !resp.usage && resp.content.length > 0;
  const tokPerSec = resp.usage && resp.generationMs > 50
    ? resp.usage.completion_tokens / (resp.generationMs / 1000)
    : null;

  return {
    truncated: resp.truncated,
    finishReason: resp.finishReason || 'unknown',
    thinkBlocksStripped: hadThinkBlocks,
    thinkStripFallback: resp.thinkStripFallback ?? false,
    estimatedTokens: estimated,
    contentLength: resp.content.length,
    generationMs: resp.generationMs,
    tokPerSec,
  };
}

function formatQualityLine(quality: QualitySignal): string {
  const flags: string[] = [];
  if (quality.truncated) flags.push('TRUNCATED');
  if (quality.thinkStripFallback) flags.push('think-strip-empty (showing raw reasoning — model ignored enable_thinking:false)');
  else if (quality.thinkBlocksStripped) flags.push('think-blocks-stripped');
  if (quality.estimatedTokens) flags.push('tokens-estimated');
  if (quality.finishReason === 'length') flags.push('hit-max-tokens');
  if (flags.length === 0) return '';
  return `Quality: ${flags.join(', ')}`;
}

/**
 * Format a footer line for streaming results showing model, usage, and truncation status.
 */
function formatFooter(resp: StreamingResult, extra?: string): string {
  // Record usage for session tracking before formatting
  recordUsage(resp);

  const parts: string[] = [];
  if (resp.model) parts.push(`Model: ${resp.model}`);
  if (resp.usage) {
    parts.push(`${resp.usage.prompt_tokens}→${resp.usage.completion_tokens} tokens`);
  } else if (resp.content.length > 0) {
    // Estimate when usage is missing (truncated responses where final SSE chunk was lost)
    const estTokens = Math.ceil(resp.content.length / 4);
    parts.push(`~${estTokens} tokens (estimated)`);
  }

  // Perf stats — computed from streaming, no proprietary API needed
  const perfParts: string[] = [];
  if (resp.ttftMs !== undefined) perfParts.push(`TTFT: ${resp.ttftMs}ms`);
  if (resp.usage && resp.generationMs > 50) {
    const tokPerSec = resp.usage.completion_tokens / (resp.generationMs / 1000);
    perfParts.push(`${tokPerSec.toFixed(1)} tok/s`);
  }
  if (resp.generationMs) perfParts.push(`${(resp.generationMs / 1000).toFixed(1)}s`);
  if (perfParts.length > 0) parts.push(perfParts.join(', '));

  if (extra) parts.push(extra);

  // Quality signals — structured metadata for orchestrator trust decisions
  const quality = assessQuality(resp, resp.rawContent);
  const qualityLine = formatQualityLine(quality);
  if (qualityLine) parts.push(qualityLine);
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
      'ROUTING: If multiple models are loaded, houtini-lm automatically picks the best one for the task. ' +
      'If a better model is downloaded but not loaded, you\'ll see a suggestion in the response footer. ' +
      'Call discover to see what\'s available.',
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
        json_schema: {
          type: 'object',
          description: 'Force structured JSON output. Provide a JSON Schema object and the response will be guaranteed valid JSON conforming to it. Example: {"name":"result","schema":{"type":"object","properties":{"answer":{"type":"string"}},"required":["answer"]}}',
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
        json_schema: {
          type: 'object',
          description: 'Force structured JSON output. Provide a JSON Schema object and the response will be guaranteed valid JSON conforming to it.',
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
    name: 'code_task_files',
    description:
      'Like code_task, but the local LLM reads the files directly from disk — the contents never pass through the MCP client\'s context window.\n\n' +
      'USE THIS instead of code_task when you want the LLM to review multiple files or a single large file, without copying source into the chat.\n\n' +
      'HOW IT WORKS:\n' +
      '• Provide absolute paths to the files you want analysed.\n' +
      '• The server reads each file (Promise.allSettled — one unreadable file does not sink the call).\n' +
      '• Files are concatenated with `=== <filename> ===` headers, then sent to the same code-review pipeline as code_task.\n' +
      '• Read failures are surfaced inline (with the reason) so the LLM can still reason about what it did receive.\n\n' +
      'WHEN TO USE:\n' +
      '• Reviewing multiple related files (module + its tests, client + server pair)\n' +
      '• Auditing a single large file too big to paste comfortably\n' +
      '• Any code_task where saving MCP client tokens matters\n\n' +
      'QA: Same rules as code_task — verify the output before acting on it.',
    inputSchema: {
      type: 'object' as const,
      properties: {
        paths: {
          type: 'array',
          items: { type: 'string' },
          description: 'Absolute file paths to analyse. Relative paths are rejected — always pass absolute.',
        },
        task: {
          type: 'string',
          description: 'What to do: "Find bugs", "Explain this module", "Suggest a cleaner API", etc.',
        },
        language: {
          type: 'string',
          description: 'Optional language hint: "typescript", "python", etc. Shapes the system prompt.',
        },
        max_tokens: {
          type: 'number',
          description: 'Optional output budget override. Defaults to 25% of the loaded model\'s context window.',
        },
      },
      required: ['paths', 'task'],
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
      'List all models on the local LLM server — both loaded (ready) and available (downloaded but not active). ' +
      'Shows rich metadata for each model: type (llm/vlm/embeddings), architecture, quantization, context window, ' +
      'and a capability profile describing what the model is best at. ' +
      'Use this to understand which models are available and suggest switching when a different model would suit the task better.',
    inputSchema: { type: 'object' as const, properties: {} },
  },
  {
    name: 'embed',
    description:
      'Generate text embeddings via the local LLM server. Requires an embedding model to be loaded ' +
      '(e.g. Nomic Embed). Returns a vector representation of the input text for semantic search, ' +
      'similarity comparison, or RAG pipelines. Uses the OpenAI-compatible /v1/embeddings endpoint.',
    inputSchema: {
      type: 'object' as const,
      properties: {
        input: {
          type: 'string',
          description: 'The text to embed. Can be a single string.',
        },
        model: {
          type: 'string',
          description: 'Embedding model ID. If omitted, uses whatever embedding model is loaded.',
        },
      },
      required: ['input'],
    },
  },
];

// ── MCP Server ───────────────────────────────────────────────────────

const server = new Server(
  { name: 'houtini-lm', version: '2.9.0' },
  { capabilities: { tools: {}, resources: {} } },
);

// ── MCP Resources ─────────────────────────────────────────────────────
// Exposes session performance metrics as a readable resource so Claude can
// proactively check offload efficiency and make smarter delegation decisions.

server.setRequestHandler(ListResourcesRequestSchema, async () => ({
  resources: [
    {
      uri: 'houtini://metrics/session',
      name: 'Session Offload Metrics',
      description: 'Cumulative token offload stats, per-model performance, and quality signals for the current session.',
      mimeType: 'application/json',
    },
  ],
}));

server.setRequestHandler(ReadResourceRequestSchema, async (request) => {
  const { uri } = request.params;

  if (uri === 'houtini://metrics/session') {
    const modelStats: Record<string, { calls: number; avgTtftMs: number; avgTokPerSec: number | null }> = {};
    for (const [modelId, stats] of session.modelStats) {
      modelStats[modelId] = {
        calls: stats.calls,
        avgTtftMs: stats.calls > 0 ? Math.round(stats.totalTtftMs / stats.calls) : 0,
        avgTokPerSec: stats.perfCalls > 0 ? parseFloat((stats.totalTokPerSec / stats.perfCalls).toFixed(1)) : null,
      };
    }

    const metrics = {
      session: {
        totalCalls: session.calls,
        promptTokens: session.promptTokens,
        completionTokens: session.completionTokens,
        totalTokensOffloaded: session.promptTokens + session.completionTokens,
      },
      perModel: modelStats,
      endpoint: LM_BASE_URL,
    };

    return {
      contents: [{
        uri,
        mimeType: 'application/json',
        text: JSON.stringify(metrics, null, 2),
      }],
    };
  }

  throw new Error(`Unknown resource: ${uri}`);
});

server.setRequestHandler(ListToolsRequestSchema, async () => ({ tools: TOOLS }));

server.setRequestHandler(CallToolRequestSchema, async (request) => {
  const { name, arguments: args } = request.params;
  const progressToken = request.params._meta?.progressToken;

  try {
    switch (name) {
      case 'chat': {
        const { message, system, temperature, max_tokens, json_schema } = args as {
          message: string;
          system?: string;
          temperature?: number;
          max_tokens?: number;
          json_schema?: { name: string; schema: Record<string, unknown>; strict?: boolean };
        };

        const route = await routeToModel('chat');
        const messages: ChatMessage[] = [];
        // Inject output constraint into system prompt if the model needs it
        const systemContent = system
          ? (route.hints.outputConstraint ? `${system}\n\n${route.hints.outputConstraint}` : system)
          : (route.hints.outputConstraint || undefined);
        if (systemContent) messages.push({ role: 'system', content: systemContent });
        messages.push({ role: 'user', content: message });

        const responseFormat: ResponseFormat | undefined = json_schema
          ? { type: 'json_schema', json_schema: { name: json_schema.name, strict: json_schema.strict ?? true, schema: json_schema.schema } }
          : undefined;

        const resp = await chatCompletionStreaming(messages, {
          temperature: temperature ?? route.hints.chatTemp,
          maxTokens: max_tokens,
          model: route.modelId,
          responseFormat,
          progressToken,
        });

        const footer = formatFooter(resp);
        return { content: [{ type: 'text', text: resp.content + footer }] };
      }

      case 'custom_prompt': {
        const { system, context, instruction, temperature, max_tokens, json_schema } = args as {
          system?: string;
          context?: string;
          instruction: string;
          temperature?: number;
          max_tokens?: number;
          json_schema?: { name: string; schema: Record<string, unknown>; strict?: boolean };
        };

        const route = await routeToModel('analysis');
        const messages: ChatMessage[] = [];
        const systemContent = system
          ? (route.hints.outputConstraint ? `${system}\n\n${route.hints.outputConstraint}` : system)
          : (route.hints.outputConstraint || undefined);
        if (systemContent) messages.push({ role: 'system', content: systemContent });

        // Multi-turn format prevents context bleed in smaller models.
        // Context goes in a separate user→assistant exchange so the model
        // "acknowledges" it before receiving the actual instruction.
        if (context) {
          messages.push({ role: 'user', content: `Here is the context for analysis:\n\n${context}` });
          messages.push({ role: 'assistant', content: 'Understood. I have read the full context. What would you like me to do with it?' });
        }
        messages.push({ role: 'user', content: instruction });

        const responseFormat: ResponseFormat | undefined = json_schema
          ? { type: 'json_schema', json_schema: { name: json_schema.name, strict: json_schema.strict ?? true, schema: json_schema.schema } }
          : undefined;

        const resp = await chatCompletionStreaming(messages, {
          temperature: temperature ?? route.hints.chatTemp,
          maxTokens: max_tokens,
          model: route.modelId,
          responseFormat,
          progressToken,
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
        const route = await routeToModel('code');
        const outputConstraint = route.hints.outputConstraint
          ? ` ${route.hints.outputConstraint}`
          : '';

        // Task goes in system message so smaller models don't lose it once
        // the code block fills the attention window. Code is sole user content.
        const codeMessages: ChatMessage[] = [
          {
            role: 'system',
            content: `Expert ${lang} developer. Your task: ${task}\n\nBe specific — reference line numbers, function names, and concrete fixes. Output your analysis as a markdown list.${outputConstraint}`,
          },
          {
            role: 'user',
            content: `\`\`\`${lang}\n${code}\n\`\`\``,
          },
        ];

        const codeResp = await chatCompletionStreaming(codeMessages, {
          temperature: route.hints.codeTemp,
          maxTokens: codeMaxTokens ?? DEFAULT_MAX_TOKENS,
          model: route.modelId,
          progressToken,
        });

        const codeFooter = formatFooter(codeResp, lang);
        const suggestionLine = route.suggestion ? `\n${route.suggestion}` : '';
        return { content: [{ type: 'text', text: codeResp.content + codeFooter + suggestionLine }] };
      }

      case 'code_task_files': {
        const { paths, task, language, max_tokens: codeMaxTokens } = args as {
          paths: string[];
          task: string;
          language?: string;
          max_tokens?: number;
        };

        if (!Array.isArray(paths) || paths.length === 0) {
          return {
            content: [{ type: 'text', text: 'Error: paths must be a non-empty array of absolute file paths.' }],
            isError: true,
          };
        }

        // Reject relative paths early — silent resolution against cwd is surprising.
        const relative = paths.filter((p) => typeof p !== 'string' || !isAbsolute(p));
        if (relative.length > 0) {
          return {
            content: [{ type: 'text', text: `Error: all paths must be absolute. Relative paths: ${JSON.stringify(relative)}` }],
            isError: true,
          };
        }

        // Read all files in parallel. One unreadable file doesn't sink the call —
        // failures become inline error sections so the model can still reason about
        // the rest of the bundle.
        const reads = await Promise.allSettled(
          paths.map(async (p) => ({ path: p, content: await readFile(p, 'utf8') })),
        );

        const sections: string[] = [];
        let successCount = 0;
        reads.forEach((r, i) => {
          const p = paths[i];
          if (r.status === 'fulfilled') {
            successCount++;
            sections.push(`=== ${basename(p)} (${p}) ===\n${r.value.content}`);
          } else {
            const reason = r.reason instanceof Error ? r.reason.message : String(r.reason);
            sections.push(`=== ${basename(p)} (${p}) — READ FAILED ===\n[Could not read: ${reason}]`);
          }
        });

        if (successCount === 0) {
          return {
            content: [{ type: 'text', text: `Error: none of the ${paths.length} file(s) could be read. Check the paths and permissions.\n\n${sections.join('\n\n')}` }],
            isError: true,
          };
        }

        const lang = language || 'unknown';
        const route = await routeToModel('code');
        const outputConstraint = route.hints.outputConstraint
          ? ` ${route.hints.outputConstraint}`
          : '';

        const combined = sections.join('\n\n');
        const codeMessages: ChatMessage[] = [
          {
            role: 'system',
            content: `Expert ${lang} developer. Your task: ${task}\n\nThe user has provided ${paths.length} file(s), concatenated below with \`=== filename ===\` headers. Reference files by name in your output. Be specific — line numbers, function names, concrete fixes. Output your analysis as a markdown list.${outputConstraint}`,
          },
          {
            role: 'user',
            content: `\`\`\`${lang}\n${combined}\n\`\`\``,
          },
        ];

        // Pass codeMaxTokens raw (not `?? DEFAULT_MAX_TOKENS`) so the 25%-of-context
        // auto-derivation in chatCompletionStreamingInner fires when the caller omits it.
        const codeResp = await chatCompletionStreaming(codeMessages, {
          temperature: route.hints.codeTemp,
          maxTokens: codeMaxTokens,
          model: route.modelId,
          progressToken,
        });

        const readSummary = successCount === paths.length
          ? `${paths.length} file(s) read`
          : `${successCount}/${paths.length} file(s) read`;
        const codeFooter = formatFooter(codeResp, `${lang} · ${readSummary}`);
        const suggestionLine = route.suggestion ? `\n${route.suggestion}` : '';
        return { content: [{ type: 'text', text: codeResp.content + codeFooter + suggestionLine }] };
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

        const loaded = models.filter((m) => m.state === 'loaded' || !m.state);
        const available = models.filter((m) => m.state === 'not-loaded');

        const primary = loaded[0] || models[0];
        const ctx = getContextLength(primary);
        const primaryProfile = await getModelProfileAsync(primary);

        const sessionStats = session.calls > 0
          ? `\nSession stats: ${(session.promptTokens + session.completionTokens).toLocaleString()} tokens offloaded across ${session.calls} call${session.calls === 1 ? '' : 's'}`
          : '\nSession stats: no calls yet — delegate tasks to start saving tokens';

        let text =
          `Status: ONLINE\n` +
          `Endpoint: ${LM_BASE_URL}\n` +
          `Latency: ${ms}ms\n` +
          `Active model: ${primary.id}\n` +
          `Context window: ${ctx.toLocaleString()} tokens\n`;

        if (primaryProfile) {
          text += `Family: ${primaryProfile.family}\n`;
          text += `Description: ${primaryProfile.description}\n`;
          text += `Best for: ${primaryProfile.bestFor.join(', ')}\n`;
          text += `Strengths: ${primaryProfile.strengths.join(', ')}\n`;
          if (primaryProfile.weaknesses.length > 0) {
            text += `Weaknesses: ${primaryProfile.weaknesses.join(', ')}\n`;
          }
        }

        if (loaded.length > 0) {
          text += `\nLoaded models (● ready to use):\n`;
          text += (await Promise.all(loaded.map((m) => formatModelDetail(m)))).join('\n\n');
        }

        if (available.length > 0) {
          text += `\n\nAvailable models (○ downloaded, not loaded — can be activated in LM Studio):\n`;
          text += (await Promise.all(available.map((m) => formatModelDetail(m)))).join('\n\n');
        }

        // Per-model performance stats from this session
        if (session.modelStats.size > 0) {
          text += `\n\nPerformance (this session):\n`;
          for (const [modelId, stats] of session.modelStats) {
            const avgTtft = stats.calls > 0 ? Math.round(stats.totalTtftMs / stats.calls) : 0;
            const avgTokSec = stats.perfCalls > 0 ? (stats.totalTokPerSec / stats.perfCalls).toFixed(1) : '?';
            text += `  ${modelId}: ${stats.calls} calls, avg TTFT ${avgTtft}ms, avg ${avgTokSec} tok/s\n`;
          }
        }

        text += `${sessionStats}\n\n`;
        text += `The local LLM is available. You can delegate tasks using chat, custom_prompt, code_task, code_task_files, or embed.`;

        return { content: [{ type: 'text', text }] };
      }

      case 'list_models': {
        const models = await listModelsRaw();
        if (!models.length) {
          return { content: [{ type: 'text', text: 'No models currently loaded or available.' }] };
        }

        const loaded = models.filter((m) => m.state === 'loaded' || !m.state);
        const available = models.filter((m) => m.state === 'not-loaded');

        let text = '';

        // list_models enriches with HuggingFace data (cached after first call)
        if (loaded.length > 0) {
          text += `Loaded models (● ready to use):\n\n`;
          text += (await Promise.all(loaded.map((m) => formatModelDetail(m, true)))).join('\n\n');
        }

        if (available.length > 0) {
          if (text) text += '\n\n';
          text += `Available models (○ downloaded, not loaded):\n\n`;
          text += (await Promise.all(available.map((m) => formatModelDetail(m, true)))).join('\n\n');
        }

        return { content: [{ type: 'text', text }] };
      }

      case 'embed': {
        const { input, model: embedModel } = args as { input: string; model?: string };

        return await withInferenceLock(async () => {
          const embedBody: Record<string, unknown> = { input };
          if (embedModel) {
            embedBody.model = embedModel;
          }

          const res = await fetchWithTimeout(
            `${LM_BASE_URL}/v1/embeddings`,
            { method: 'POST', headers: apiHeaders(), body: JSON.stringify(embedBody) },
            INFERENCE_CONNECT_TIMEOUT_MS,
          );

          if (!res.ok) {
            const errText = await res.text().catch(() => '');
            throw new Error(`Embeddings API error ${res.status}: ${errText}`);
          }

          const data = (await res.json()) as {
            data: { embedding: number[]; index: number }[];
            model: string;
            usage?: { prompt_tokens: number; total_tokens: number };
          };

          const embedding = data.data[0]?.embedding;
          if (!embedding) throw new Error('No embedding returned');

          const usageInfo = data.usage
            ? `${data.usage.prompt_tokens} tokens embedded`
            : '';

          return {
            content: [{
              type: 'text',
              text: JSON.stringify({
                model: data.model,
                dimensions: embedding.length,
                embedding,
                usage: usageInfo,
              }),
            }],
          };
        });
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

  // Background: profile all available models via HF → SQLite cache
  // Non-blocking — server is already accepting requests
  listModelsRaw()
    .then((models) => profileModelsAtStartup(models))
    .catch((err) => process.stderr.write(`[houtini-lm] Startup profiling skipped: ${err}\n`));
}

main().catch((error) => {
  process.stderr.write(`Fatal error: ${error}\n`);
  process.exit(1);
});
