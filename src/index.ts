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
  recordPerformance,
  getAllPerformance,
  getLifetimeTotals,
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
const READ_CHUNK_TIMEOUT_MS = 30_000;        // max wait for a single SSE chunk mid-stream
const PREFILL_TIMEOUT_MS = 180_000;          // max wait for the FIRST chunk — prompt prefill on slow hardware with big inputs can legitimately take 1-2 min
const PREFILL_KEEPALIVE_MS = 10_000;         // fire a progress notification every N ms while waiting for prefill to finish
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
  modelStats: new Map<string, { calls: number; ttftCalls: number; perfCalls: number; totalTtftMs: number; totalTokPerSec: number }>(),
};

// Lifetime mirror — kept in sync with the SQLite `model_performance` table
// so the footer/discover path stays synchronous. Hydrated once at startup
// from `getAllPerformance()`, then updated in-memory alongside every DB
// write in `recordUsage`. Also updated after the async DB write completes
// so counters can only ever run a tick behind, never ahead.
const lifetime = {
  totalCalls: 0,
  totalTokens: 0,
  modelsUsed: 0,
  firstSeenAt: null as number | null,
  /** Per-model lifetime stats — same shape as session.modelStats for easy formatting. */
  modelStats: new Map<string, { calls: number; ttftCalls: number; perfCalls: number; totalTtftMs: number; totalTokPerSec: number; totalPromptTokens: number; firstSeenAt: number; lastUsedAt: number }>(),
};

async function hydrateLifetimeFromDb(): Promise<void> {
  try {
    const totals = await getLifetimeTotals();
    lifetime.totalCalls = totals.totalCalls;
    lifetime.totalTokens = totals.totalTokens;
    lifetime.modelsUsed = totals.modelsUsed;
    lifetime.firstSeenAt = totals.firstSeenAt;

    const rows = await getAllPerformance();
    lifetime.modelStats.clear();
    for (const r of rows) {
      lifetime.modelStats.set(r.modelId, {
        calls: r.totalCalls,
        ttftCalls: r.ttftCalls,
        perfCalls: r.perfCalls,
        totalTtftMs: r.totalTtftMs,
        totalTokPerSec: r.totalTokPerSec,
        totalPromptTokens: r.totalPromptTokens,
        firstSeenAt: r.firstSeenAt,
        lastUsedAt: r.lastUsedAt,
      });
    }
  } catch (err) {
    process.stderr.write(`[houtini-lm] Lifetime hydration failed (stats will build from this session): ${err}\n`);
  }
}

function recordUsage(resp: StreamingResult) {
  session.calls++;
  const promptTokens = resp.usage?.prompt_tokens ?? 0;
  let completionTokens = resp.usage?.completion_tokens ?? 0;
  const reasoningTokens = resp.usage?.completion_tokens_details?.reasoning_tokens ?? 0;
  if (resp.usage) {
    session.promptTokens += promptTokens;
    session.completionTokens += completionTokens;
  } else if (resp.content.length > 0) {
    // Estimate when usage is missing (truncated responses)
    const est = Math.ceil(resp.content.length / 4);
    completionTokens = est;
    session.completionTokens += est;
  }

  // Tok/s used by both session and lifetime stats
  const tokPerSec = resp.usage && resp.generationMs > 50
    ? (resp.usage.completion_tokens / (resp.generationMs / 1000))
    : 0;

  // Session per-model (unchanged behaviour)
  if (resp.model) {
    const existing = session.modelStats.get(resp.model) || { calls: 0, ttftCalls: 0, perfCalls: 0, totalTtftMs: 0, totalTokPerSec: 0 };
    existing.calls++;
    if (resp.ttftMs) {
      existing.totalTtftMs += resp.ttftMs;
      existing.ttftCalls++;
    }
    if (tokPerSec > 0) {
      existing.perfCalls++;
      existing.totalTokPerSec += tokPerSec;
    }
    session.modelStats.set(resp.model, existing);
  }

  // Lifetime mirror + SQLite write — fire-and-forget so a DB hiccup can't
  // stall a tool response. The in-memory mirror is updated synchronously so
  // the footer and discover output reflect this call immediately.
  if (resp.model && (promptTokens > 0 || completionTokens > 0)) {
    const now = Date.now();
    const wasFirstEver = !lifetime.modelStats.has(resp.model);
    const lExisting = lifetime.modelStats.get(resp.model) || {
      calls: 0, ttftCalls: 0, perfCalls: 0, totalTtftMs: 0, totalTokPerSec: 0, totalPromptTokens: 0,
      firstSeenAt: now, lastUsedAt: now,
    };
    lExisting.calls++;
    if (resp.ttftMs) {
      lExisting.totalTtftMs += resp.ttftMs;
      lExisting.ttftCalls++;
    }
    if (tokPerSec > 0) {
      lExisting.perfCalls++;
      lExisting.totalTokPerSec += tokPerSec;
    }
    lExisting.totalPromptTokens += promptTokens;
    lExisting.lastUsedAt = now;
    lifetime.modelStats.set(resp.model, lExisting);

    lifetime.totalCalls++;
    lifetime.totalTokens += promptTokens + completionTokens;
    if (wasFirstEver) {
      lifetime.modelsUsed++;
      if (lifetime.firstSeenAt === null) lifetime.firstSeenAt = now;
    }

    recordPerformance(resp.model, {
      ttftMs: resp.ttftMs,
      tokPerSec: tokPerSec > 0 ? tokPerSec : undefined,
      promptTokens,
      completionTokens,
      reasoningTokens,
    }).catch((err) => {
      process.stderr.write(`[houtini-lm] Performance write failed (continuing): ${err}\n`);
    });
  }
}

function sessionSummary(): string {
  const total = session.promptTokens + session.completionTokens;
  if (session.calls === 0 && lifetime.totalCalls === 0) return '';

  const callWord = (n: number) => (n === 1 ? 'call' : 'calls');
  const sessionPart = session.calls > 0
    ? `this session: ${total.toLocaleString()} tokens / ${session.calls} ${callWord(session.calls)}`
    : 'this session: 0 tokens';

  // Lifetime numbers only show once there's something in the DB — avoids a
  // confusing "lifetime: 0" on a truly fresh install.
  if (lifetime.totalCalls > 0) {
    return `💰 Claude quota saved — ${sessionPart} · lifetime: ${lifetime.totalTokens.toLocaleString()} tokens / ${lifetime.totalCalls} ${callWord(lifetime.totalCalls)}`;
  }
  return `💰 Claude quota saved ${sessionPart}`;
}

/**
 * Return true when this response is the first one with measurable perf stats
 * for its model in the current session. Used to surface a one-off "benchmarked"
 * line so Claude sees the real speed of the local model on a genuine task,
 * not an artificial warmup.
 */
function isFirstBenchmarkedCall(modelId: string, tokPerSec: number): boolean {
  if (!modelId || tokPerSec <= 0) return false;
  const stats = session.modelStats.get(modelId);
  // After recordUsage has run, perfCalls === 1 means this was the first measured call.
  return !!stats && stats.perfCalls === 1;
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
  /** Reasoning content streamed via OpenAI vendor extension delta.reasoning_content */
  reasoningContent?: string;
  model: string;
  usage?: {
    prompt_tokens: number;
    completion_tokens: number;
    total_tokens: number;
    /** OpenAI: how many of the completion tokens were reasoning (hidden) */
    completion_tokens_details?: { reasoning_tokens?: number };
  };
  finishReason: string;
  truncated: boolean;
  /** Time to first token in milliseconds */
  ttftMs?: number;
  /** Total generation time in milliseconds */
  generationMs: number;
  /** True when think-block stripping left nothing and we fell back to raw content */
  thinkStripFallback?: boolean;
  /** True when no visible content arrived and we fell back to reasoning_content */
  reasoningFallback?: boolean;
  /** Truncation caused by prefill stall (no chunks received) vs mid-stream stall */
  prefillStall?: boolean;
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
    // Send max_completion_tokens alongside max_tokens for OpenAI reasoning-model
    // compatibility (OpenAI spec distinguishes total generation cap from visible
    // output cap). Backends that don't understand it ignore unknown fields.
    max_completion_tokens: effectiveMaxTokens,
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
  // Some models (Gemma 4, Qwen3, DeepSeek R1, Nemotron, gpt-oss) have extended
  // thinking that consumes part of the max_tokens budget for invisible reasoning
  // before producing content. Strategy:
  //   1. reasoning_effort=<family-specific value> to minimise reasoning
  //   2. enable_thinking:false — Qwen3 vendor param (ignored elsewhere)
  //   3. inflate max_tokens 4× — safety net when both flags are ignored
  //      (e.g. Gemma 4 hardcodes enable_thinking=true in its Jinja template)
  //
  // IMPORTANT: reasoning_effort values are NOT standard. OpenAI/gpt-oss use
  // 'low'|'medium'|'high'; Ollama adds 'none'; LM Studio's Nemotron adapter
  // only accepts 'on'|'off'. Sending 'low' to Nemotron causes LM Studio to
  // silently fall back to 'on' — maximising reasoning, the OPPOSITE of intent.
  // Hence the family-specific mapping below. When uncertain, we omit the
  // field entirely rather than risk a bad-value fallback.
  const modelId = (options.model || LM_MODEL || '').toString();
  if (modelId) {
    const thinking = await getThinkingSupport(modelId);
    if (thinking?.supportsThinkingToggle) {
      body.enable_thinking = false;
      const reasoningValue = getReasoningEffortValue(modelId);
      if (reasoningValue !== null) {
        body.reasoning_effort = reasoningValue;
      }
      // Inflation uses effectiveMaxTokens (the context-aware value), not
      // DEFAULT_MAX_TOKENS — otherwise big-context models get sized down.
      const beforeInflation = effectiveMaxTokens;
      const inflated = Math.max(beforeInflation * 4, beforeInflation + 2000);
      body.max_tokens = inflated;
      body.max_completion_tokens = inflated;
      process.stderr.write(`[houtini-lm] Thinking model ${modelId}: reasoning_effort=${reasoningValue ?? '(omitted)'}, enable_thinking=false, max_tokens inflated ${beforeInflation} → ${inflated}\n`);
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
  let reasoning = '';
  let progressSeq = 0;
  let model = '';
  let usage: StreamingResult['usage'];
  let finishReason = '';
  let truncated = false;
  let prefillStall = false;
  let buffer = '';
  let ttftMs: number | undefined;
  let firstChunkReceived = false;

  // Prefill keep-alive — /v1/chat/completions gives no SSE events during
  // prompt processing, so the MCP client clock ticks uninterrupted on a slow
  // backend with a big input. Fire a progress notification every 10s until
  // the first chunk arrives to keep the client from timing out at 60s.
  const sendProgress = (message: string) => {
    if (options.progressToken === undefined) return;
    progressSeq++;
    server.notification({
      method: 'notifications/progress',
      params: {
        progressToken: options.progressToken,
        progress: progressSeq,
        message,
      },
    }).catch(() => { /* best-effort — don't break streaming */ });
  };

  const keepAliveTimer: ReturnType<typeof setInterval> = setInterval(() => {
    if (firstChunkReceived) return;
    const waitedMs = Date.now() - startTime;
    sendProgress(`Waiting for model... (${(waitedMs / 1000).toFixed(0)}s, still in prefill)`);
  }, PREFILL_KEEPALIVE_MS);

  try {
    while (true) {
      // Check soft timeout before each read
      const elapsed = Date.now() - startTime;
      if (elapsed > SOFT_TIMEOUT_MS) {
        truncated = true;
        process.stderr.write(`[houtini-lm] Soft timeout at ${elapsed}ms, returning ${content.length} chars of partial content\n`);
        break;
      }

      // Split prefill vs mid-stream timeouts. Prefill on slow hardware with
      // a 7k-token input can legitimately take 1-2 min; mid-stream stalls
      // should surface much faster. Track firstChunkReceived to switch.
      const remaining = SOFT_TIMEOUT_MS - elapsed;
      const perChunkCeiling = firstChunkReceived ? READ_CHUNK_TIMEOUT_MS : PREFILL_TIMEOUT_MS;
      const chunkTimeout = Math.min(perChunkCeiling, remaining);
      const result = await timedRead(reader, chunkTimeout);

      if (result === 'timeout') {
        truncated = true;
        prefillStall = !firstChunkReceived;
        process.stderr.write(`[houtini-lm] ${prefillStall ? 'Prefill' : 'Mid-stream'} timeout, returning ${content.length} chars of partial content\n`);
        break;
      }

      if (result.done) break;

      if (!firstChunkReceived) {
        firstChunkReceived = true;
      }

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

          // Reasoning channel. LM Studio (with "Separate reasoning_content"
          // dev setting), DeepSeek R1, Ollama OpenAI-compat, Nemotron etc.
          // stream reasoning via delta.reasoning_content — we MUST capture it
          // so the safety net below can return something when the model
          // burns its entire budget before emitting a single content token.
          if (typeof delta?.reasoning_content === 'string' && delta.reasoning_content.length > 0) {
            reasoning += delta.reasoning_content;
            sendProgress(`Thinking... (${reasoning.length} chars of reasoning)`);
          }

          if (typeof delta?.content === 'string' && delta.content.length > 0) {
            if (ttftMs === undefined) ttftMs = Date.now() - startTime;
            content += delta.content;
            sendProgress(`Streaming... ${content.length} chars`);
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
          if (typeof delta?.reasoning_content === 'string' && delta.reasoning_content.length > 0) {
            reasoning += delta.reasoning_content;
          }
          if (typeof delta?.content === 'string' && delta.content.length > 0) {
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
    clearInterval(keepAliveTimer);
    // Best-effort cancel with a short timeout — cancel() can hang if the upstream
    // connection is wedged, so we race it against a 500ms timer. This frees the
    // underlying socket sooner on abrupt client disconnects without blocking the
    // tool response path.
    try {
      await Promise.race([
        reader.cancel().catch(() => { /* ignore */ }),
        new Promise<void>((resolve) => setTimeout(resolve, 500)),
      ]);
    } catch { /* never propagate cleanup errors */ }
    try { reader.releaseLock(); } catch { /* already released */ }
  }

  const generationMs = Date.now() - startTime;

  // Strip <think>...</think> reasoning blocks from models that always emit them
  // inline on the content channel (e.g. GLM Flash). Claude doesn't need the
  // model's internal reasoning. Handle both closed and unclosed blocks.
  let cleanContent = content.replace(/<think>[\s\S]*?<\/think>\s*/g, '');  // closed blocks
  cleanContent = cleanContent.replace(/^<think>\s*/, '');                   // orphaned opening tag
  cleanContent = cleanContent.trim();

  // Safety nets for empty visible output. Try in order:
  //   1. thinkStripFallback: stripping <think> left nothing, but raw content had text
  //   2. reasoningFallback: no visible content AT ALL, but reasoning_content was streamed
  //      (this is the Nemotron/DeepSeek-R1/LM-Studio-dev-toggle case — previously
  //      produced silent empty bodies because reasoning was discarded)
  let thinkStripFallback = false;
  let reasoningFallback = false;
  if (!cleanContent) {
    if (content.trim()) {
      thinkStripFallback = true;
      cleanContent = content.trim();
    } else if (reasoning.trim()) {
      reasoningFallback = true;
      cleanContent =
        '[No visible output — the model spent its entire output budget on reasoning_content before emitting any content. ' +
        'Raw reasoning below so you can see what it was doing:]\n\n' +
        reasoning.trim();
    }
  }

  return {
    content: cleanContent,
    rawContent: content,
    reasoningContent: reasoning || undefined,
    model,
    usage,
    finishReason,
    truncated,
    ttftMs,
    generationMs,
    thinkStripFallback,
    reasoningFallback,
    prefillStall,
  };
}

// Backend detection. Probed once on first listModelsRaw() call, cached for
// the session. We keep inference on the portable /v1/chat/completions path
// regardless of backend — this flag is for enrichment (richer model metadata,
// accurate "it's LM Studio, so the dev-toggle for reasoning_content matters"
// hints in diagnostics, etc.).
type Backend = 'lmstudio' | 'ollama' | 'openai-compat';
let detectedBackend: Backend | null = null;

function getBackend(): Backend {
  return detectedBackend ?? 'openai-compat';
}

/**
 * Fetch models with backend-aware probing.
 *   1. LM Studio /api/v0/models — richest metadata, sets backend='lmstudio'
 *   2. Ollama /api/tags           — native list, sets backend='ollama', maps to ModelInfo
 *   3. OpenAI-compatible /v1/models — generic fallback (DeepSeek, vLLM, llama.cpp, OpenRouter)
 */
async function listModelsRaw(): Promise<ModelInfo[]> {
  // Try LM Studio's v0 API first — returns type, arch, publisher, quantization, state
  try {
    const v0 = await fetchWithTimeout(
      `${LM_BASE_URL}/api/v0/models`,
      { headers: apiHeaders() },
    );
    if (v0.ok) {
      const data = (await v0.json()) as { data: ModelInfo[] };
      detectedBackend = 'lmstudio';
      return data.data;
    }
  } catch {
    // v0 not available — fall through
  }

  // Try Ollama's /api/tags next. Shape differs from OpenAI: returns
  // { models: [{ name, model, size, details: { family, parameter_size, ... } }] }
  try {
    const tags = await fetchWithTimeout(
      `${LM_BASE_URL}/api/tags`,
      { headers: apiHeaders() },
    );
    if (tags.ok) {
      const data = (await tags.json()) as {
        models?: Array<{
          name: string;
          model?: string;
          size?: number;
          details?: { family?: string; parameter_size?: string; quantization_level?: string };
        }>;
      };
      if (Array.isArray(data.models)) {
        detectedBackend = 'ollama';
        return data.models.map((m) => ({
          id: m.name,
          object: 'model',
          type: 'llm',
          arch: m.details?.family,
          quantization: m.details?.quantization_level,
          state: 'loaded', // Ollama loads on-demand; treat all listed as available
          publisher: m.name.includes('/') ? m.name.split('/')[0] : undefined,
        }));
      }
    }
  } catch {
    // Not Ollama — fall through
  }

  // Fallback: OpenAI-compatible v1 endpoint (DeepSeek, vLLM, llama.cpp, OpenRouter)
  const res = await fetchWithTimeout(
    `${LM_BASE_URL}/v1/models`,
    { headers: apiHeaders() },
  );
  if (!res.ok) throw new Error(`Failed to list models: ${res.status}`);
  const data = (await res.json()) as { data: ModelInfo[] };
  detectedBackend = 'openai-compat';
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

/**
 * Map model family / backend → reasoning_effort value that minimises reasoning.
 *
 * The `reasoning_effort` field exists across OpenAI, Ollama, LM Studio and
 * DeepSeek, but the accepted values differ per vendor. Verified empirically
 * from the LM Studio error response: "Supported values: none, minimal, low,
 * medium, high, xhigh" (that's the set the LM Studio adapter accepts).
 *
 *   OpenAI (gpt-5, o-series)        : 'low' | 'medium' | 'high' (spec)
 *   Ollama                          : 'low' | 'medium' | 'high' | 'none'
 *   LM Studio (all models)          : 'none' | 'minimal' | 'low' | 'medium' | 'high' | 'xhigh'
 *
 * We want the HARDEST off-switch we can portably send:
 *   - LM Studio / Ollama: 'none'  (no reasoning budget at all)
 *   - Generic OpenAI-compat: 'low' (OpenAI's minimum, safe to send)
 *
 * An unsupported value is a hard 400 error on LM Studio (not a silent
 * fallback), so this function is conservative — it returns null for
 * unknown backends and we omit the field rather than risk a 400.
 */
function getReasoningEffortValue(_modelId: string): string | null {
  const backend = getBackend();
  // LM Studio accepts 'none' as an explicit reasoning-off switch for
  // every thinking model (Nemotron, DeepSeek R1, Gemma 4, gpt-oss, ...).
  if (backend === 'lmstudio') return 'none';
  // Ollama likewise documents 'none' as valid.
  if (backend === 'ollama') return 'none';
  // Generic OpenAI-compatible — 'low' is the minimum OpenAI accepts per spec.
  // DeepSeek's own API treats 'low' as minimum too.
  return 'low';
}

/** Rough chars→tokens ratio used for pre-flight estimates. Matches the ratio
 * we already use to estimate completion_tokens when usage is missing. */
const CHARS_PER_TOKEN = 4;

/** Conservative default prefill rate when no per-model measurement exists.
 * Slower than real hardware so we err toward letting the call run — a false
 * refusal is much worse than a false-ok that eventually times out. */
const DEFAULT_PREFILL_TOK_PER_SEC = 300;

/** Hard ceiling for when we refuse to send the call. Leaves ~15s of
 * generation headroom inside the ~60s MCP-client request-timeout budget. */
const PREFILL_REFUSE_THRESHOLD_SEC = 45;

/** Soft warning threshold — we proceed but log a stderr warning. */
const PREFILL_WARN_THRESHOLD_SEC = 25;

interface PrefillEstimate {
  inputTokens: number;
  estimatedSeconds: number;
  prefillTokPerSec: number;
  basis: 'measured' | 'default';
}

/**
 * Estimate how long prompt prefill will take, using measured per-model data
 * from the SQLite cache when available. `totalTtftMs` is very close to pure
 * prefill time for a streaming call (first-content-delta arrives right after
 * prefill finishes), so `totalPromptTokens / totalTtftMs` gives a usable
 * prefill-tok/s rate for that specific (model, hardware) pair.
 */
function estimatePrefill(inputChars: number, modelId: string): PrefillEstimate {
  const inputTokens = Math.ceil(inputChars / CHARS_PER_TOKEN);
  const stats = lifetime.modelStats.get(modelId);
  let prefillTokPerSec = DEFAULT_PREFILL_TOK_PER_SEC;
  let basis: 'measured' | 'default' = 'default';

  if (stats && stats.ttftCalls >= 2 && stats.totalTtftMs > 0 && stats.totalPromptTokens > 0) {
    // Only trust measured data after >=2 TTFT samples — single samples on a
    // cold model run are noisy. Average prompt tokens per call approximated
    // as totalPromptTokens / calls, then divided by average TTFT seconds.
    const avgPromptTokens = stats.totalPromptTokens / stats.calls;
    const avgTtftSec = (stats.totalTtftMs / stats.ttftCalls) / 1000;
    if (avgTtftSec > 0) {
      prefillTokPerSec = avgPromptTokens / avgTtftSec;
      basis = 'measured';
    }
  }

  return {
    inputTokens,
    estimatedSeconds: inputTokens / prefillTokPerSec,
    prefillTokPerSec,
    basis,
  };
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
  prefillStall: boolean;       // truncation occurred before any chunk arrived
  finishReason: string;
  thinkBlocksStripped: boolean;
  thinkStripFallback: boolean;  // strip emptied content; returning raw as fallback
  reasoningFallback: boolean;   // no visible content; returning raw reasoning_content
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
    prefillStall: resp.prefillStall ?? false,
    finishReason: resp.finishReason || 'unknown',
    thinkBlocksStripped: hadThinkBlocks,
    thinkStripFallback: resp.thinkStripFallback ?? false,
    reasoningFallback: resp.reasoningFallback ?? false,
    estimatedTokens: estimated,
    contentLength: resp.content.length,
    generationMs: resp.generationMs,
    tokPerSec,
  };
}

function formatQualityLine(quality: QualitySignal): string {
  const flags: string[] = [];
  if (quality.prefillStall) flags.push('PREFILL-STALL (no tokens received — input may be too large for this model/hardware)');
  else if (quality.truncated) flags.push('TRUNCATED');
  if (quality.reasoningFallback) flags.push('reasoning-only (model exhausted output budget before emitting visible content — showing raw reasoning)');
  else if (quality.thinkStripFallback) flags.push('think-strip-empty (showing raw reasoning — model ignored enable_thinking:false)');
  else if (quality.thinkBlocksStripped) flags.push('think-blocks-stripped');
  if (quality.estimatedTokens) flags.push('tokens-estimated');
  if (quality.finishReason === 'length') flags.push('hit-max-tokens');
  if (flags.length === 0) return '';
  return `Quality: ${flags.join(', ')}`;
}

/**
 * Format a footer line for streaming results showing model, usage, and truncation status.
 *
 * Layout:
 *   ---
 *   Model: ... | prompt→completion tokens | perf | extra | quality
 *   📊 [first-call benchmark line, only on the first measured call per model]
 *   💰 Claude quota saved this session: ...
 */
function formatFooter(resp: StreamingResult, extra?: string): string {
  // Record usage for session tracking before formatting
  recordUsage(resp);

  const parts: string[] = [];
  if (resp.model) parts.push(`Model: ${resp.model}`);
  if (resp.usage) {
    // OpenAI-spec reasoning-tokens split — when present, show it so the user
    // sees how much of the completion budget went to hidden reasoning vs
    // visible output. Diagnoses "empty body + hit-max-tokens" immediately.
    const reasoningTokens = resp.usage.completion_tokens_details?.reasoning_tokens;
    if (typeof reasoningTokens === 'number' && reasoningTokens > 0) {
      const visible = resp.usage.completion_tokens - reasoningTokens;
      parts.push(`${resp.usage.prompt_tokens}→${resp.usage.completion_tokens} tokens (${reasoningTokens} reasoning / ${visible} visible)`);
    } else {
      parts.push(`${resp.usage.prompt_tokens}→${resp.usage.completion_tokens} tokens`);
    }
  } else if (resp.content.length > 0) {
    // Estimate when usage is missing (truncated responses where final SSE chunk was lost)
    const estTokens = Math.ceil(resp.content.length / 4);
    parts.push(`~${estTokens} tokens (estimated)`);
  }

  // Perf stats — computed from streaming, no proprietary API needed
  const perfParts: string[] = [];
  if (resp.ttftMs !== undefined) perfParts.push(`TTFT: ${resp.ttftMs}ms`);
  let tokPerSec = 0;
  if (resp.usage && resp.generationMs > 50) {
    tokPerSec = resp.usage.completion_tokens / (resp.generationMs / 1000);
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

  const benchmarkLine = isFirstBenchmarkedCall(resp.model, tokPerSec)
    ? `📊 First measured call on ${resp.model}: ${tokPerSec.toFixed(1)} tok/s${resp.ttftMs !== undefined ? `, ${resp.ttftMs}ms to first token` : ''} — use this to gauge whether to delegate longer tasks.`
    : '';
  const sessionLine = sessionSummary();

  if (parts.length === 0 && !benchmarkLine && !sessionLine) return '';

  const lines: string[] = [`\n\n---${parts.length > 0 ? `\n${parts.join(' | ')}` : ''}`];
  // First-call speed benchmark — surfaced once per model per session, based on
  // the real task just completed (not a synthetic warmup). Gives Claude honest
  // speed data to calibrate future delegation decisions.
  if (benchmarkLine) lines.push(benchmarkLine);
  // Session savings — on its own line so it reads as value, not as accounting.
  if (sessionLine) lines.push(sessionLine);

  return lines.join('\n');
}

// ── MCP Tool definitions ─────────────────────────────────────────────

const TOOLS = [
  {
    name: 'chat',
    description:
      'Send a task to a local LLM — a sidekick running on the user\'s hardware or a configured OpenAI-compatible endpoint. ' +
      'It does not consume the user\'s Claude quota. Trades latency for tokens: local inference is typically 3-30× slower than frontier models, so delegation wins when the task is bounded and self-contained.\n\n' +
      'Good fit:\n' +
      '• Explain or summarise code/docs you already have in context\n' +
      '• Generate boilerplate, test stubs, type definitions, mock data\n' +
      '• Answer factual questions about languages, frameworks, APIs\n' +
      '• Draft commit messages, PR descriptions, comments\n' +
      '• Translate or reformat content (JSON↔YAML, snake_case↔camelCase)\n' +
      '• Brainstorm approaches before committing to one\n\n' +
      'Less good when: the task needs tool access, depends on multi-file context you have not captured, or is quick enough for you to answer directly before the round-trip completes.\n\n' +
      'Prompt tips (local models take instructions literally):\n' +
      '(1) Send COMPLETE context — the local LLM cannot read files.\n' +
      '(2) Be explicit about output format ("respond as a JSON array", "return only the function").\n' +
      '(3) Specific system persona beats generic — "Senior TypeScript dev" not "helpful assistant".\n' +
      '(4) State constraints — "no preamble", "reference line numbers", "max 5 bullets".\n\n' +
      'Routing picks the best loaded model automatically. Call `discover` to see what is loaded and, after the first real call, its measured speed. The footer shows cumulative tokens kept in the user\'s quota.',
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
          description: 'Max response tokens. Defaults to 25% of the loaded model\'s context window (fallback 16,384). Pass a number to cap it tighter for quick answers.',
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
      'The 3-part format prevents context bleed in smaller models — the local LLM acknowledges the context in a fake assistant turn before receiving the instruction.\n\n' +
      'Good fit when prompt structure matters:\n' +
      '• Code review — paste full source, ask for bugs/improvements\n' +
      '• Comparison — paste two implementations, ask which is better and why\n' +
      '• Refactoring suggestions — paste code, ask for a cleaner version\n' +
      '• Content analysis — paste text, ask for structure/tone/issues\n' +
      '• Any task where separating context from instruction improves clarity\n\n' +
      'Field guidance (each has a job — keep them focused):\n' +
      '• system: persona + constraints, under 30 words. "Expert Python developer focused on performance and correctness."\n' +
      '• context: COMPLETE data — full source, full logs, full text. Never truncate.\n' +
      '• instruction: exactly what to produce, under 50 words. Specify format: "Return a JSON array of {line, issue, fix}."\n\n' +
      'Review the output before acting on it — local model capability varies.',
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
          description: 'Max response tokens. Defaults to 25% of the loaded model\'s context window (fallback 16,384).',
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
      'Send a code-specific task to the local LLM, wrapped with an optimised code-review system prompt. Temperature is locked low (0.2 or the routed model\'s hint) for deterministic output.\n\n' +
      'Good fit:\n' +
      '• Explain what a function/class does\n' +
      '• Find bugs or suggest improvements\n' +
      '• Generate unit tests or type definitions for existing code\n' +
      '• Add error handling, logging, or validation\n' +
      '• Convert between languages or patterns\n\n' +
      'For best results:\n' +
      '• Provide COMPLETE source — the local LLM cannot read files.\n' +
      '• Include imports and type definitions so the model has full context.\n' +
      '• Be specific: "Write 3 Jest tests for the error paths in fetchUser" beats "Write tests".\n' +
      '• Set the language field — it shapes the system prompt and improves accuracy.\n\n' +
      'Verify generated code compiles, handles edge cases, and follows project conventions before committing.',
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
          description: 'Max response tokens. Defaults to 25% of the loaded model\'s context window (fallback 16,384).',
        },
      },
      required: ['code', 'task'],
    },
  },
  {
    name: 'code_task_files',
    description:
      'Like code_task, but the local LLM reads files directly from disk — source never passes through the MCP client\'s context window. Use when reviewing multiple files or a single large file.\n\n' +
      'How it works:\n' +
      '• Provide absolute paths. Relative paths are rejected.\n' +
      '• Files are read in parallel (Promise.allSettled) — one unreadable file does not sink the call.\n' +
      '• Files are concatenated with `=== filename ===` headers and sent to the same code-review pipeline as code_task.\n' +
      '• Read failures are surfaced inline with the reason so the LLM can still reason about the rest.\n' +
      '• Pre-flight prefill estimate: if measured per-model data shows the input would exceed the MCP client\'s ~60s request timeout during prompt processing, the call is refused early with a diagnostic instead of hanging. Split or trim when this fires.\n\n' +
      'Good fit:\n' +
      '• Reviewing related files together (module + its tests, client + server pair)\n' +
      '• Auditing a single large file too big to paste comfortably\n' +
      '• Any code_task where keeping source out of the Claude context window matters\n\n' +
      'Size guidance: on slow hardware (< 25 tok/s generation), keep total input under ~8,000 tokens (~32,000 chars) to stay safely under the client timeout. Faster hardware handles much more — the pre-flight estimator adapts once you\'ve done a few calls and real per-model timings are in the SQLite cache.\n\n' +
      'Same review discipline as code_task — verify the output before acting on it.',
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
  {
    name: 'stats',
    description:
      'Show user stats: tokens offloaded, calls made, per-model performance — for the current session AND ' +
      'lifetime (persisted in SQLite at ~/.houtini-lm/model-cache.db). Unlike `discover` which includes the ' +
      'model catalog, `stats` returns just the numbers in a compact markdown table — cheap to call repeatedly ' +
      'to see the 💰 Claude-quota savings counter climb. Useful for quantifying how much work the local model ' +
      'is genuinely doing, and for noticing when a model\'s reasoning-token ratio is drifting.',
    inputSchema: {
      type: 'object' as const,
      properties: {
        model: {
          type: 'string',
          description: 'Optional: filter output to a single model ID. Omit to see all models this workstation has used.',
        },
      },
    },
  },
];

// ── MCP Server ───────────────────────────────────────────────────────

// Session-level sidekick framing. MCP clients surface this to the model
// at initialisation, so it sets the baseline expectation for when to delegate
// rather than relying on per-tool descriptions being re-read on every call.
const SIDEKICK_INSTRUCTIONS =
  `Houtini-lm is a local LLM sidekick. It runs on the user's hardware (or a configured OpenAI-compatible endpoint) and handles bounded work without consuming the user's Claude quota.\n\n` +
  `When to reach for it: bounded, self-contained tasks you can describe in one message — explanations, boilerplate, test stubs, code review of pasted or file-loaded source, translations, commit messages, format conversion, brainstorming. Trades wall-clock time for tokens (typically 3-30× slower than frontier models).\n\n` +
  `When not to: tasks that need tool access, cross-file reasoning you haven't captured, or work fast enough to answer directly before the delegation round-trip completes.\n\n` +
  `Call \`discover\` in delegation-heavy sessions to see what model is loaded, its capability profile, and — after the first real call — its measured speed. The response footer reports cumulative tokens kept in the user's quota.`;

const server = new Server(
  { name: 'houtini-lm', version: '2.11.0' },
  { capabilities: { tools: {}, resources: {} }, instructions: SIDEKICK_INSTRUCTIONS },
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
        avgTtftMs: stats.ttftCalls > 0 ? Math.round(stats.totalTtftMs / stats.ttftCalls) : 0,
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

        // Pre-flight prefill estimate. Huge inputs can legitimately exceed
        // the MCP client's ~60s request timeout during prompt processing, and
        // progress notifications don't reset that timeout on Claude Desktop.
        // If measured per-model data in the SQLite cache shows this input
        // would obviously overrun, refuse with a concrete diagnostic so the
        // caller knows to split or trim instead of waiting for a silent hang.
        const estimate = estimatePrefill(combined.length, route.modelId);
        if (estimate.basis === 'measured' && estimate.estimatedSeconds > PREFILL_REFUSE_THRESHOLD_SEC) {
          const prefillRate = Math.round(estimate.prefillTokPerSec);
          const estSec = Math.round(estimate.estimatedSeconds);
          return {
            content: [{
              type: 'text',
              text:
                `Error: estimated prefill time exceeds the ~60s MCP client timeout.\n\n` +
                `• Input size: ~${estimate.inputTokens.toLocaleString()} tokens across ${successCount} file(s)\n` +
                `• Measured prefill rate on ${route.modelId}: ~${prefillRate} tok/s (from ${lifetime.modelStats.get(route.modelId)?.ttftCalls ?? 0} prior calls)\n` +
                `• Estimated prefill: ~${estSec}s (threshold: ${PREFILL_REFUSE_THRESHOLD_SEC}s)\n\n` +
                `Options: split the files into smaller groups, trim the largest file, or use \`code_task\` with a focused excerpt. ` +
                `If you know this workstation can handle it, pass fewer files or run the task again when the measured rate improves.`,
            }],
            isError: true,
          };
        }
        if (estimate.estimatedSeconds > PREFILL_WARN_THRESHOLD_SEC) {
          process.stderr.write(
            `[houtini-lm] Large input warning: ~${estimate.inputTokens} tokens, est prefill ~${Math.round(estimate.estimatedSeconds)}s (${estimate.basis}). Proceeding.\n`,
          );
        }

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

        // Use sessionSummary() so discover matches the footer format and
        // automatically picks up the lifetime line when the SQLite cache has
        // cross-session data.
        const summary = sessionSummary();
        const sessionStats = session.calls > 0 || lifetime.totalCalls > 0
          ? `\n${summary}`
          : `\n💰 Claude quota saved this session: 0 tokens — no calls yet. Measured speed for each model will appear here after the first real call.`;

        // Measured speed line for the active model. Discover intentionally does
        // not run a synthetic warmup — speed is captured from real tasks, so the
        // numbers reflect actual workload rather than a contrived benchmark.
        // Shows session stats when this session has measured calls; otherwise
        // falls back to workstation lifetime stats so Claude sees historical
        // perf from call 1 instead of "not yet benchmarked".
        const primaryStats = session.modelStats.get(primary.id);
        const primaryLifetime = lifetime.modelStats.get(primary.id);
        let speedLine = '';
        if (primaryStats && primaryStats.perfCalls > 0) {
          const avgTtft = primaryStats.ttftCalls > 0 ? Math.round(primaryStats.totalTtftMs / primaryStats.ttftCalls) : 0;
          const avgTokSec = (primaryStats.totalTokPerSec / primaryStats.perfCalls).toFixed(1);
          speedLine = `Measured speed (session): ${avgTokSec} tok/s · TTFT ${avgTtft}ms (${primaryStats.perfCalls} call${primaryStats.perfCalls === 1 ? '' : 's'})\n`;
          if (primaryLifetime && primaryLifetime.perfCalls > primaryStats.perfCalls) {
            const lAvgTtft = primaryLifetime.ttftCalls > 0 ? Math.round(primaryLifetime.totalTtftMs / primaryLifetime.ttftCalls) : 0;
            const lAvgTokSec = (primaryLifetime.totalTokPerSec / primaryLifetime.perfCalls).toFixed(1);
            speedLine += `Measured speed (lifetime on this workstation): ${lAvgTokSec} tok/s · TTFT ${lAvgTtft}ms (${primaryLifetime.perfCalls} calls)\n`;
          }
        } else if (primaryLifetime && primaryLifetime.perfCalls > 0) {
          const lAvgTtft = primaryLifetime.ttftCalls > 0 ? Math.round(primaryLifetime.totalTtftMs / primaryLifetime.ttftCalls) : 0;
          const lAvgTokSec = (primaryLifetime.totalTokPerSec / primaryLifetime.perfCalls).toFixed(1);
          speedLine = `Measured speed (lifetime on this workstation): ${lAvgTokSec} tok/s · TTFT ${lAvgTtft}ms (${primaryLifetime.perfCalls} calls, last used ${new Date(primaryLifetime.lastUsedAt).toISOString().slice(0, 10)})\n`;
        } else {
          speedLine = `Measured speed: not yet benchmarked — will be captured on the first real call.\n`;
        }

        const backendLabel = getBackend() === 'lmstudio' ? 'LM Studio'
          : getBackend() === 'ollama' ? 'Ollama'
          : 'OpenAI-compatible';

        let text =
          `Status: ONLINE\n` +
          `Endpoint: ${LM_BASE_URL} (${backendLabel})\n` +
          `Connection latency: ${ms}ms (does not reflect inference speed)\n` +
          `Active model: ${primary.id}\n` +
          `Context window: ${ctx.toLocaleString()} tokens\n` +
          speedLine;

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
            const avgTtft = stats.ttftCalls > 0 ? Math.round(stats.totalTtftMs / stats.ttftCalls) : 0;
            const avgTokSec = stats.perfCalls > 0 ? (stats.totalTokPerSec / stats.perfCalls).toFixed(1) : '?';
            text += `  ${modelId}: ${stats.calls} calls, avg TTFT ${avgTtft}ms, avg ${avgTokSec} tok/s\n`;
          }
        }

        // Workstation lifetime stats — built from SQLite, persists across restarts.
        // Only shown when there's lifetime data beyond this session, so a first-run
        // user doesn't see a duplicate of the session block above.
        const hasLifetimeBeyondSession = Array.from(lifetime.modelStats.entries())
          .some(([id, l]) => l.calls > (session.modelStats.get(id)?.calls ?? 0));
        if (hasLifetimeBeyondSession) {
          text += `\nPerformance (lifetime on this workstation):\n`;
          for (const [modelId, stats] of lifetime.modelStats) {
            const avgTtft = stats.ttftCalls > 0 ? Math.round(stats.totalTtftMs / stats.ttftCalls) : 0;
            const avgTokSec = stats.perfCalls > 0 ? (stats.totalTokPerSec / stats.perfCalls).toFixed(1) : '?';
            const lastUsed = new Date(stats.lastUsedAt).toISOString().slice(0, 10);
            text += `  ${modelId}: ${stats.calls} calls, avg TTFT ${avgTtft}ms, avg ${avgTokSec} tok/s (last used ${lastUsed})\n`;
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

      case 'stats': {
        const { model: filterModel } = args as { model?: string };

        const backendLabel = getBackend() === 'lmstudio' ? 'LM Studio'
          : getBackend() === 'ollama' ? 'Ollama'
          : 'OpenAI-compatible';

        const lines: string[] = [];
        lines.push(`## Houtini LM stats`);
        lines.push('');
        lines.push(`**Endpoint**: ${LM_BASE_URL} (${backendLabel})`);
        if (lifetime.firstSeenAt) {
          lines.push(`**First call on this workstation**: ${new Date(lifetime.firstSeenAt).toISOString().slice(0, 10)}`);
        }
        lines.push('');

        // Totals block
        lines.push(`### Totals`);
        lines.push('');
        lines.push(`| Scope    | Calls | Prompt tokens | Completion tokens | Total tokens |`);
        lines.push(`|----------|------:|--------------:|------------------:|-------------:|`);
        lines.push(`| Session  | ${session.calls} | ${session.promptTokens.toLocaleString()} | ${session.completionTokens.toLocaleString()} | ${(session.promptTokens + session.completionTokens).toLocaleString()} |`);
        lines.push(`| Lifetime | ${lifetime.totalCalls} | — | — | ${lifetime.totalTokens.toLocaleString()} |`);
        lines.push('');

        // Per-model block (union of session + lifetime model ids)
        const modelIds = new Set<string>([
          ...session.modelStats.keys(),
          ...lifetime.modelStats.keys(),
        ]);
        const filtered = filterModel ? [...modelIds].filter((m) => m === filterModel) : [...modelIds];

        if (filtered.length > 0) {
          lines.push(`### Per-model performance`);
          lines.push('');
          lines.push(`| Model | Scope | Calls | Avg TTFT (ms) | Avg tok/s | Prompt tokens | Last used |`);
          lines.push(`|-------|-------|------:|--------------:|----------:|--------------:|-----------|`);
          for (const modelId of filtered.sort()) {
            const s = session.modelStats.get(modelId);
            const l = lifetime.modelStats.get(modelId);
            if (s) {
              const avgTtft = s.ttftCalls > 0 ? Math.round(s.totalTtftMs / s.ttftCalls) : '—';
              const avgTokSec = s.perfCalls > 0 ? (s.totalTokPerSec / s.perfCalls).toFixed(1) : '—';
              lines.push(`| ${modelId} | session | ${s.calls} | ${avgTtft} | ${avgTokSec} | — | — |`);
            }
            if (l) {
              const avgTtft = l.ttftCalls > 0 ? Math.round(l.totalTtftMs / l.ttftCalls) : '—';
              const avgTokSec = l.perfCalls > 0 ? (l.totalTokPerSec / l.perfCalls).toFixed(1) : '—';
              const lastUsed = new Date(l.lastUsedAt).toISOString().slice(0, 10);
              lines.push(`| ${modelId} | lifetime | ${l.calls} | ${avgTtft} | ${avgTokSec} | ${l.totalPromptTokens.toLocaleString()} | ${lastUsed} |`);
            }
          }
          lines.push('');
        } else if (filterModel) {
          lines.push(`No history for model: \`${filterModel}\`. Try \`list_models\` to see what's been used.`);
          lines.push('');
        } else {
          lines.push(`No calls yet — delegate a task via \`chat\`, \`custom_prompt\`, \`code_task\`, or \`code_task_files\` to start building stats.`);
          lines.push('');
        }

        // Reasoning-token diagnostic (lifetime only — needs persistence to be meaningful)
        if (!filterModel) {
          // Sum reasoning tokens across all models. We store this per-model
          // in SQLite but not in the in-memory mirror, so fetch on demand.
          try {
            const rows = await getAllPerformance();
            const totalReasoning = rows.reduce((sum, r) => sum + (r.totalReasoningTokens || 0), 0);
            const totalCompletion = rows.reduce((sum, r) => sum + r.totalCompletionTokens, 0);
            if (totalCompletion > 0) {
              const pct = ((totalReasoning / totalCompletion) * 100).toFixed(1);
              lines.push(`### Reasoning-token overhead (lifetime)`);
              lines.push('');
              lines.push(`${totalReasoning.toLocaleString()} / ${totalCompletion.toLocaleString()} completion tokens spent on hidden reasoning (${pct}% of generation budget). ` +
                (parseFloat(pct) > 30
                  ? `**High** — consider loading a non-thinking model, or check that \`reasoning_effort\` is being honoured (see stderr logs).`
                  : parseFloat(pct) > 10
                    ? `Moderate — normal for thinking-model families.`
                    : `Low — reasoning is effectively suppressed.`));
              lines.push('');
            }
          } catch { /* best-effort — don't fail the tool call */ }
        }

        lines.push(`*Stats persist across restarts in \`~/.houtini-lm/model-cache.db\`.*`);

        return { content: [{ type: 'text', text: lines.join('\n') }] };
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

  // Hydrate the in-memory lifetime mirror from SQLite so the very first
  // tool call this session shows historical savings + per-model perf.
  // Non-blocking too; the footer degrades to session-only if this fails.
  hydrateLifetimeFromDb().catch((err) =>
    process.stderr.write(`[houtini-lm] Lifetime hydration skipped: ${err}\n`),
  );
}

main().catch((error) => {
  process.stderr.write(`Fatal error: ${error}\n`);
  process.exit(1);
});
