/**
 * SQLite-backed model profile cache.
 *
 * On startup, houtini-lm fetches available models from the LLM server and
 * looks up each one on HuggingFace's free API. The results are cached in a
 * local SQLite database so subsequent startups are instant (no network).
 *
 * Uses sql.js (pure WASM) — zero native deps, works everywhere.
 */

import initSqlJs, { type Database } from 'sql.js';
import { readFileSync, writeFileSync, mkdirSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import { homedir } from 'node:os';

// ── Types ────────────────────────────────────────────────────────────

export interface CachedModelProfile {
  modelId: string;
  hfId: string | null;
  pipelineTag: string | null;
  architectures: string | null;     // JSON array string
  license: string | null;
  downloads: number | null;
  likes: number | null;
  libraryName: string | null;
  // Auto-generated profile fields
  family: string | null;
  description: string | null;
  strengths: string | null;         // JSON array string
  weaknesses: string | null;        // JSON array string
  bestFor: string | null;           // JSON array string
  // Thinking / reasoning capability (detected from HF chat_template)
  emitsThinkBlocks: boolean;        // model outputs <think> blocks
  supportsThinkingToggle: boolean;  // supports enable_thinking param to suppress thinking
  // Cache metadata
  fetchedAt: number;                // Unix timestamp ms
  source: 'huggingface' | 'static' | 'inferred';
}

export interface ModelProfile {
  family: string;
  description: string;
  strengths: string[];
  weaknesses: string[];
  bestFor: string[];
}

/**
 * Persisted per-model performance record. Accumulates across sessions so
 * Claude sees real historical TTFT / tok/s from call 1 of a new session
 * (instead of "not yet benchmarked"), and so lifetime Claude-quota savings
 * survive Claude Desktop restarts. Highly personal to the workstation —
 * that's intentional; routing decisions should reflect the user's real
 * hardware, not a synthetic benchmark.
 */
export interface CachedPerformance {
  modelId: string;
  totalCalls: number;
  ttftCalls: number;          // how many calls had a measurable TTFT
  totalTtftMs: number;        // sum of TTFTs for averaging
  perfCalls: number;          // how many calls had measurable tok/s
  totalTokPerSec: number;     // sum of tok/s values for averaging
  totalPromptTokens: number;
  totalCompletionTokens: number;
  totalReasoningTokens: number;
  firstSeenAt: number;
  lastUsedAt: number;
}

// ── Prompt hints ─────────────────────────────────────────────────────
// Per-family guidance on how to get the best output from each model.
// Used by the routing layer to shape system prompts and parameters.

export interface PromptHints {
  /** Preferred temperature range for this model family */
  codeTemp: number;
  chatTemp: number;
  /** Extra system prompt suffix to constrain output format */
  outputConstraint: string;
  /** Task types this model excels at (for routing) */
  bestTaskTypes: ('code' | 'chat' | 'analysis' | 'embedding')[];
}

const PROMPT_HINTS: { pattern: RegExp; hints: PromptHints }[] = [
  {
    pattern: /glm[- ]?4/i,
    hints: {
      codeTemp: 0.1,
      chatTemp: 0.3,
      outputConstraint: 'Respond with ONLY the requested output. No step-by-step reasoning. No preamble. Use markdown formatting: bullet points for lists, fenced code blocks for code.',

      bestTaskTypes: ['chat', 'analysis'],
    },
  },
  {
    pattern: /qwen3.*coder|qwen.*coder/i,
    hints: {
      codeTemp: 0.1,
      chatTemp: 0.3,
      outputConstraint: 'Be direct. Output only what was asked for. Use markdown formatting: bullet points for lists, fenced code blocks for code. No preamble.',

      bestTaskTypes: ['code'],
    },
  },
  {
    pattern: /qwen3(?!.*coder)(?!.*vl)/i,
    hints: {
      codeTemp: 0.2,
      chatTemp: 0.3,
      outputConstraint: 'Be direct. Output only what was asked for. Use markdown formatting: bullet points for lists, fenced code blocks for code. No preamble.',

      bestTaskTypes: ['chat', 'analysis', 'code'],
    },
  },
  {
    pattern: /llama[- ]?3/i,
    hints: {
      codeTemp: 0.2,
      chatTemp: 0.4,
      outputConstraint: '',

      bestTaskTypes: ['chat', 'code', 'analysis'],
    },
  },
  {
    pattern: /nemotron/i,
    hints: {
      codeTemp: 0.1,
      chatTemp: 0.3,
      outputConstraint: '',

      bestTaskTypes: ['analysis', 'code'],
    },
  },
  {
    pattern: /granite/i,
    hints: {
      codeTemp: 0.2,
      chatTemp: 0.3,
      outputConstraint: '',

      bestTaskTypes: ['code', 'chat'],
    },
  },
  {
    pattern: /gpt[- ]?oss/i,
    hints: {
      codeTemp: 0.2,
      chatTemp: 0.4,
      outputConstraint: '',

      bestTaskTypes: ['chat', 'code', 'analysis'],
    },
  },
  {
    pattern: /nomic.*embed|embed.*nomic/i,
    hints: {
      codeTemp: 0,
      chatTemp: 0,
      outputConstraint: '',

      bestTaskTypes: ['embedding'],
    },
  },
];

/**
 * Get prompt hints for a model by ID or architecture.
 */
export function getPromptHints(modelId: string, arch?: string): PromptHints {
  for (const { pattern, hints } of PROMPT_HINTS) {
    if (pattern.test(modelId)) return hints;
    if (arch && pattern.test(arch)) return hints;
  }
  // Sensible defaults for unknown models
  return {
    codeTemp: 0.2,
    chatTemp: 0.3,
    outputConstraint: '',
    bestTaskTypes: ['chat', 'code', 'analysis'],
  };
}

// ── Constants ────────────────────────────────────────────────────────

const DB_DIR = join(homedir(), '.houtini-lm');
const DB_PATH = join(DB_DIR, 'model-cache.db');
const CACHE_TTL_MS = 7 * 24 * 60 * 60 * 1000; // 7 days
const HF_TIMEOUT_MS = 8000;

// ── Database ─────────────────────────────────────────────────────────

let db: Database | null = null;

export async function initDb(): Promise<Database> {
  if (db) return db;

  const SQL = await initSqlJs();

  // Load existing DB from disk if it exists
  if (existsSync(DB_PATH)) {
    try {
      const buf = readFileSync(DB_PATH);
      db = new SQL.Database(buf);
    } catch {
      // Corrupt DB — start fresh
      db = new SQL.Database();
    }
  } else {
    db = new SQL.Database();
  }

  // Create table if not exists
  db.run(`
    CREATE TABLE IF NOT EXISTS model_profiles (
      model_id TEXT PRIMARY KEY,
      hf_id TEXT,
      pipeline_tag TEXT,
      architectures TEXT,
      license TEXT,
      downloads INTEGER,
      likes INTEGER,
      library_name TEXT,
      family TEXT,
      description TEXT,
      strengths TEXT,
      weaknesses TEXT,
      best_for TEXT,
      emits_think_blocks INTEGER NOT NULL DEFAULT 0,
      supports_thinking_toggle INTEGER NOT NULL DEFAULT 0,
      fetched_at INTEGER NOT NULL,
      source TEXT NOT NULL DEFAULT 'huggingface'
    )
  `);

  // Migrate: add thinking columns if upgrading from older schema
  try {
    db.run('ALTER TABLE model_profiles ADD COLUMN emits_think_blocks INTEGER NOT NULL DEFAULT 0');
  } catch { /* column already exists */ }
  try {
    db.run('ALTER TABLE model_profiles ADD COLUMN supports_thinking_toggle INTEGER NOT NULL DEFAULT 0');
  } catch { /* column already exists */ }

  // Per-model performance history — accumulated across sessions.
  db.run(`
    CREATE TABLE IF NOT EXISTS model_performance (
      model_id TEXT PRIMARY KEY,
      total_calls INTEGER NOT NULL DEFAULT 0,
      ttft_calls INTEGER NOT NULL DEFAULT 0,
      total_ttft_ms INTEGER NOT NULL DEFAULT 0,
      perf_calls INTEGER NOT NULL DEFAULT 0,
      total_tok_per_sec REAL NOT NULL DEFAULT 0,
      total_prompt_tokens INTEGER NOT NULL DEFAULT 0,
      total_completion_tokens INTEGER NOT NULL DEFAULT 0,
      total_reasoning_tokens INTEGER NOT NULL DEFAULT 0,
      first_seen_at INTEGER NOT NULL,
      last_used_at INTEGER NOT NULL
    )
  `);

  // Per-call prefill samples — used by the linear-fit pre-flight estimator.
  // Stores (prompt_tokens, TTFT_ms) pairs so we can fit TTFT ≈ α + β·tokens
  // and separate fixed per-request overhead from real per-token prefill cost.
  // Capped at PREFILL_SAMPLES_PER_MODEL rows per model; oldest pruned on insert.
  db.run(`
    CREATE TABLE IF NOT EXISTS model_prefill_samples (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      model_id TEXT NOT NULL,
      prompt_tokens INTEGER NOT NULL,
      ttft_ms INTEGER NOT NULL,
      recorded_at INTEGER NOT NULL
    )
  `);
  db.run(`CREATE INDEX IF NOT EXISTS idx_prefill_samples_model ON model_prefill_samples(model_id, recorded_at DESC)`);

  return db;
}

function saveDb(): void {
  if (!db) return;
  try {
    mkdirSync(DB_DIR, { recursive: true });
    const data = db.export();
    writeFileSync(DB_PATH, Buffer.from(data));
  } catch (err) {
    process.stderr.write(`[houtini-lm] Failed to save model cache: ${err}\n`);
  }
}

// ── Cache operations ─────────────────────────────────────────────────

export async function getCachedProfile(modelId: string): Promise<CachedModelProfile | null> {
  const database = await initDb();
  const stmt = database.prepare('SELECT * FROM model_profiles WHERE model_id = ?');
  try {
    stmt.bind([modelId]);

    if (stmt.step()) {
      const row = stmt.getAsObject() as Record<string, unknown>;
      return {
        modelId: row.model_id as string,
        hfId: row.hf_id as string | null,
        pipelineTag: row.pipeline_tag as string | null,
        architectures: row.architectures as string | null,
        license: row.license as string | null,
        downloads: row.downloads as number | null,
        likes: row.likes as number | null,
        libraryName: row.library_name as string | null,
        family: row.family as string | null,
        description: row.description as string | null,
        strengths: row.strengths as string | null,
        weaknesses: row.weaknesses as string | null,
        bestFor: row.best_for as string | null,
        emitsThinkBlocks: !!(row.emits_think_blocks as number),
        supportsThinkingToggle: !!(row.supports_thinking_toggle as number),
        fetchedAt: row.fetched_at as number,
        source: row.source as 'huggingface' | 'static' | 'inferred',
      };
    }
    return null;
  } finally {
    stmt.free();
  }
}

/**
 * Insert or update a profile in the DB. Saves to disk immediately by default.
 * Pass skipSave=true during batch operations, then call flushDb() when done.
 */
export async function upsertProfile(profile: CachedModelProfile, skipSave = false): Promise<void> {
  const database = await initDb();
  database.run(
    `INSERT OR REPLACE INTO model_profiles
     (model_id, hf_id, pipeline_tag, architectures, license, downloads, likes, library_name,
      family, description, strengths, weaknesses, best_for, emits_think_blocks, supports_thinking_toggle, fetched_at, source)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    [
      profile.modelId,
      profile.hfId,
      profile.pipelineTag,
      profile.architectures,
      profile.license,
      profile.downloads,
      profile.likes,
      profile.libraryName,
      profile.family,
      profile.description,
      profile.strengths,
      profile.weaknesses,
      profile.bestFor,
      profile.emitsThinkBlocks ? 1 : 0,
      profile.supportsThinkingToggle ? 1 : 0,
      profile.fetchedAt,
      profile.source,
    ],
  );
  if (!skipSave) saveDb();
}

/** Flush DB to disk. Call after batch upsertProfile(…, true) operations. */
export function flushDb(): void {
  saveDb();
}

export function isCacheStale(profile: CachedModelProfile): boolean {
  return Date.now() - profile.fetchedAt > CACHE_TTL_MS;
}

/**
 * Convert a cached profile to the ModelProfile format used by the rest of the app.
 */
export function toModelProfile(cached: CachedModelProfile): ModelProfile | null {
  if (!cached.family || !cached.description) return null;
  return {
    family: cached.family,
    description: cached.description,
    strengths: cached.strengths ? JSON.parse(cached.strengths) : [],
    weaknesses: cached.weaknesses ? JSON.parse(cached.weaknesses) : [],
    bestFor: cached.bestFor ? JSON.parse(cached.bestFor) : [],
  };
}

// ── HuggingFace model card API ───────────────────────────────────────

interface HFModelCard {
  id: string;
  pipeline_tag?: string;
  tags?: string[];
  downloads?: number;
  likes?: number;
  library_name?: string;
  config?: {
    model_type?: string;
    architectures?: string[];
    tokenizer_config?: {
      chat_template?: string;
      [key: string]: unknown;
    };
    [key: string]: unknown;
  };
  cardData?: {
    license?: string;
    language?: string | string[];
    [key: string]: unknown;
  };
}

/**
 * Detect thinking/reasoning support from HF model metadata.
 * Uses chat_template patterns first, then falls back to architecture-based
 * detection for gated models (e.g. Gemma 4) where HF metadata is unavailable.
 */
function detectThinkingSupport(card: HFModelCard): { emitsThinkBlocks: boolean; supportsThinkingToggle: boolean } {
  const chatTemplate = card.config?.tokenizer_config?.chat_template || '';

  // Does the template reference <think> blocks at all?
  let emitsThinkBlocks = /<think>/.test(chatTemplate) || /thinking/.test(chatTemplate.toLowerCase());

  // Does the template support enable_thinking toggle? (Qwen3 pattern)
  let supportsThinkingToggle = /enable_thinking/.test(chatTemplate);

  // Arch/id-based fallback for gated or quantised repos where chat_template is
  // missing. Reuses the same patterns as the arch-only path so both detection
  // routes agree on what counts as a thinking model.
  if (!supportsThinkingToggle) {
    const arch = card.config?.architectures?.[0] || '';
    const fallback = detectThinkingSupportFromArch(arch, card.id || '');
    if (fallback.supportsThinkingToggle) {
      emitsThinkBlocks = true;
      supportsThinkingToggle = true;
    }
  }

  return { emitsThinkBlocks, supportsThinkingToggle };
}

/**
 * Detect thinking support from LM Studio model metadata alone (no HF card).
 * Used when HF lookup fails (gated models, offline, etc.).
 */
function detectThinkingSupportFromArch(arch: string, modelId: string): { emitsThinkBlocks: boolean; supportsThinkingToggle: boolean } {
  const archLower = (arch || '').toLowerCase();
  const idLower = (modelId || '').toLowerCase();

  // Architectures that default to extended reasoning. We flag them as
  // thinking-capable so the inference layer inflates max_tokens and sends
  // reasoning_effort:"low" (portable across OpenAI, Ollama, LM Studio,
  // DeepSeek R1, gpt-oss). Detection uses both arch and id because HF cards
  // for gated/quant'd repos sometimes strip the chat_template.
  const thinkingArchitectures = [
    'gemma4',         // Gemma 4 — enable_thinking hardcoded true in Jinja
    'nemotron',       // NVIDIA Nemotron reasoning models (nemotron_h, nemotron_h_moe)
    'deepseek2',      // DeepSeek R1 / V3 reasoning variants stream reasoning_content
    'glm4',           // Zhipu GLM-4 — chain-of-thought in-band
    'gpt-oss',        // OpenAI open-source reasoning model
    'gpt_oss',
  ];

  const thinkingIdPatterns = [
    /gemma-4/i,
    /gemma4/i,
    /nemotron/i,      // nvidia/nemotron-3-nano etc.
    /deepseek-?r1/i,  // DeepSeek-R1 family
    /gpt-?oss/i,      // openai/gpt-oss-20b
    /qwen3.*thinking/i,
    /\bthinking\b/i,  // any model tagged "-thinking"
  ];

  const isThinking = thinkingArchitectures.some(a => archLower.includes(a))
    || thinkingIdPatterns.some(p => p.test(idLower));

  return {
    emitsThinkBlocks: isThinking,
    supportsThinkingToggle: isThinking,
  };
}

async function fetchHF(url: string): Promise<Response> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), HF_TIMEOUT_MS);
  try {
    return await fetch(url, { headers: { Accept: 'application/json' }, signal: controller.signal });
  } finally {
    clearTimeout(timer);
  }
}

/**
 * Try to find a model on HuggingFace given a local model ID and optional publisher.
 * Returns the HF card or null.
 */
async function lookupHF(modelId: string, publisher?: string): Promise<HFModelCard | null> {
  const candidates: string[] = [];

  if (modelId.includes('/')) {
    candidates.push(modelId);
  }
  if (publisher && !modelId.includes('/')) {
    candidates.push(`${publisher}/${modelId}`);
  }

  for (const hfId of candidates) {
    try {
      const res = await fetchHF(`https://huggingface.co/api/models/${hfId}`);
      if (res.ok) return (await res.json()) as HFModelCard;
    } catch {
      // skip
    }
  }
  return null;
}

// ── Auto-profile generation ──────────────────────────────────────────
// When HF gives us metadata but we don't have a hardcoded profile,
// generate a reasonable one from the available data.

function inferProfileFromHF(card: HFModelCard, modelId: string): Partial<CachedModelProfile> {
  const tag = card.pipeline_tag || '';
  const tags = card.tags || [];
  const arch = card.config?.architectures?.[0] || '';

  // Extract org/family from HF ID
  const parts = card.id.split('/');
  const org = parts.length > 1 ? parts[0] : '';
  const modelName = parts.length > 1 ? parts[1] : parts[0];

  // Infer family name from model ID
  const family = inferFamily(modelName, org);

  // Infer description
  let description = `${org ? org + "'s " : ''}${family} model.`;
  if (tag === 'text-generation') description += ' Text generation / chat model.';
  else if (tag === 'image-text-to-text') description += ' Vision-language model — handles text and image inputs.';
  else if (tag === 'feature-extraction' || tag === 'sentence-similarity') description += ' Embedding model for semantic search.';
  if (card.cardData?.license) description += ` License: ${card.cardData.license}.`;

  // Infer strengths from tags
  const strengths: string[] = [];
  const weaknesses: string[] = [];
  const bestFor: string[] = [];

  if (tag === 'text-generation') {
    strengths.push('text generation', 'instruction following');
    bestFor.push('general delegation', 'Q&A');
  }
  if (tag === 'image-text-to-text') {
    strengths.push('image understanding', 'visual Q&A');
    bestFor.push('screenshot analysis', 'diagram interpretation');
  }
  if (tags.includes('code') || modelName.toLowerCase().includes('code')) {
    strengths.push('code generation');
    bestFor.push('code tasks');
  }
  if (tags.includes('math') || modelName.toLowerCase().includes('math')) {
    strengths.push('mathematics', 'reasoning');
    bestFor.push('math/science questions');
  }
  if (tags.includes('conversational')) {
    strengths.push('conversation');
    bestFor.push('chat', 'brainstorming');
  }

  // Default if nothing specific found
  if (strengths.length === 0) strengths.push('general reasoning');
  if (bestFor.length === 0) bestFor.push('general delegation');

  const thinking = detectThinkingSupport(card);

  return {
    family,
    description,
    strengths: JSON.stringify(strengths),
    weaknesses: JSON.stringify(weaknesses),
    bestFor: JSON.stringify(bestFor),
    emitsThinkBlocks: thinking.emitsThinkBlocks,
    supportsThinkingToggle: thinking.supportsThinkingToggle,
  };
}

function inferFamily(modelName: string, org: string): string {
  // Try to extract a clean family name from the model ID
  // e.g. "glm-4.7-flash" -> "GLM-4", "qwen3-coder-30b" -> "Qwen3 Coder"
  const lower = modelName.toLowerCase();

  // Common patterns
  const familyPatterns: [RegExp, string][] = [
    [/^glm[- ]?(\d)/i, 'GLM-$1'],
    [/^qwen(\d)[- ]?coder/i, 'Qwen$1 Coder'],
    [/^qwen(\d)[- ]?vl/i, 'Qwen$1 VL'],
    [/^qwen(\d)/i, 'Qwen$1'],
    [/^llama[- ]?(\d)/i, 'LLaMA $1'],
    [/^nemotron/i, 'Nemotron'],
    [/^granite/i, 'Granite'],
    [/^mistral/i, 'Mistral'],
    [/^mixtral/i, 'Mixtral'],
    [/^deepseek/i, 'DeepSeek'],
    [/^phi[- ]?(\d)/i, 'Phi-$1'],
    [/^gemma[- ]?(\d)/i, 'Gemma $1'],
    [/^starcoder/i, 'StarCoder'],
    [/^codestral/i, 'Codestral'],
    [/^command[- ]?r/i, 'Command R'],
    [/^internlm/i, 'InternLM'],
    [/^yi[- ]?(\d)/i, 'Yi-$1'],
    [/^nomic/i, 'Nomic'],
    [/^gpt[- ]?oss/i, 'GPT-OSS'],
    [/^minimax/i, 'MiniMax'],
    [/^kimi/i, 'Kimi'],
  ];

  for (const [pattern, replacement] of familyPatterns) {
    if (pattern.test(lower)) {
      return modelName.replace(pattern, replacement);
    }
  }

  // Fallback: use org + first meaningful part of name
  const firstPart = modelName.split(/[-_ ]/)[0];
  return org ? `${org}/${firstPart}` : firstPart;
}

// ── Startup profiling ────────────────────────────────────────────────

interface ModelInfoForCache {
  id: string;
  publisher?: string;
  arch?: string;
  type?: string;
}

/**
 * Profile all models at startup. For each model:
 * 1. Check SQLite cache — if fresh, skip
 * 2. Look up on HuggingFace — if found, auto-generate profile and cache
 * 3. If HF miss, cache as "inferred" with whatever metadata we have
 *
 * Runs in the background — never blocks server startup.
 */
export async function profileModelsAtStartup(models: ModelInfoForCache[]): Promise<void> {
  const database = await initDb();
  let profiledCount = 0;
  let cachedCount = 0;

  for (const model of models) {
    try {
      // Check cache
      const cached = await getCachedProfile(model.id);
      if (cached && !isCacheStale(cached)) {
        cachedCount++;
        continue;
      }

      // Look up on HuggingFace
      const card = await lookupHF(model.id, model.publisher);

      if (card) {
        const inferred = inferProfileFromHF(card, model.id);
        await upsertProfile({
          modelId: model.id,
          hfId: card.id,
          pipelineTag: card.pipeline_tag || null,
          architectures: card.config?.architectures ? JSON.stringify(card.config.architectures) : null,
          license: card.cardData?.license || null,
          downloads: card.downloads || null,
          likes: card.likes || null,
          libraryName: card.library_name || null,
          family: inferred.family || null,
          description: inferred.description || null,
          strengths: inferred.strengths || null,
          weaknesses: inferred.weaknesses || null,
          bestFor: inferred.bestFor || null,
          emitsThinkBlocks: inferred.emitsThinkBlocks || false,
          supportsThinkingToggle: inferred.supportsThinkingToggle || false,
          fetchedAt: Date.now(),
          source: 'huggingface',
        }, true);
        profiledCount++;
      } else {
        // No HF match — cache a minimal profile so we don't retry.
        // Use architecture-based thinking detection as fallback for gated models.
        const thinking = detectThinkingSupportFromArch(model.arch || '', model.id);
        if (thinking.supportsThinkingToggle) {
          process.stderr.write(`[houtini-lm] Detected thinking model from arch/id: ${model.id} (arch: ${model.arch}) — will suppress thinking\n`);
        }
        await upsertProfile({
          modelId: model.id,
          hfId: null,
          pipelineTag: model.type || null,
          architectures: model.arch ? JSON.stringify([model.arch]) : null,
          license: null,
          downloads: null,
          likes: null,
          libraryName: null,
          family: inferFamily(model.id.split('/').pop() || model.id, model.publisher || ''),
          description: `${model.publisher ? model.publisher + "'s " : ''}local model. No HuggingFace card found.`,
          strengths: null,
          weaknesses: null,
          bestFor: null,
          emitsThinkBlocks: thinking.emitsThinkBlocks,
          supportsThinkingToggle: thinking.supportsThinkingToggle,
          fetchedAt: Date.now(),
          source: 'inferred',
        }, true);
        profiledCount++;
      }
    } catch (err) {
      process.stderr.write(`[houtini-lm] Failed to profile ${model.id}: ${err}\n`);
    }
  }

  // Flush all changes to disk in one write
  if (profiledCount > 0) flushDb();

  process.stderr.write(
    `[houtini-lm] Model cache: ${cachedCount} cached, ${profiledCount} profiled, ${models.length} total\n`,
  );
}

/**
 * Get a profile for display — checks SQLite first, returns formatted enrichment line.
 */
export async function getHFEnrichmentLine(modelId: string): Promise<string> {
  const cached = await getCachedProfile(modelId);
  if (!cached || cached.source === 'inferred') return '';

  const parts: string[] = [];
  if (cached.pipelineTag) parts.push(`HF task: ${cached.pipelineTag}`);
  if (cached.libraryName) parts.push(`library: ${cached.libraryName}`);
  if (cached.downloads) parts.push(`${cached.downloads.toLocaleString()} downloads`);
  if (cached.likes) parts.push(`${cached.likes.toLocaleString()} likes`);
  if (cached.license) parts.push(`license: ${cached.license}`);
  if (cached.architectures) {
    try {
      const archs = JSON.parse(cached.architectures) as string[];
      if (archs.length) parts.push(`HF arch: ${archs.join(', ')}`);
    } catch { /* skip */ }
  }
  return parts.length > 0 ? `    HuggingFace: ${parts.join(' · ')}` : '';
}

/**
 * Get all cached profiles (for diagnostics or export).
 */
export async function getAllCachedProfiles(): Promise<CachedModelProfile[]> {
  const database = await initDb();
  const results: CachedModelProfile[] = [];
  const stmt = database.prepare('SELECT * FROM model_profiles ORDER BY model_id');
  while (stmt.step()) {
    const row = stmt.getAsObject() as Record<string, unknown>;
    results.push({
      modelId: row.model_id as string,
      hfId: row.hf_id as string | null,
      pipelineTag: row.pipeline_tag as string | null,
      architectures: row.architectures as string | null,
      license: row.license as string | null,
      downloads: row.downloads as number | null,
      likes: row.likes as number | null,
      libraryName: row.library_name as string | null,
      family: row.family as string | null,
      description: row.description as string | null,
      strengths: row.strengths as string | null,
      weaknesses: row.weaknesses as string | null,
      bestFor: row.best_for as string | null,
      emitsThinkBlocks: !!(row.emits_think_blocks as number),
      supportsThinkingToggle: !!(row.supports_thinking_toggle as number),
      fetchedAt: row.fetched_at as number,
      source: row.source as 'huggingface' | 'static' | 'inferred',
    });
  }
  stmt.free();
  return results;
}

/**
 * Query thinking support for a model from the cache.
 * Returns null if model is not cached.
 */
export async function getThinkingSupport(modelId: string): Promise<{ emitsThinkBlocks: boolean; supportsThinkingToggle: boolean } | null> {
  const cached = await getCachedProfile(modelId);

  // Re-apply the arch/id fallback at read time so newly-recognised thinking
  // architectures (e.g. Nemotron, DeepSeek-R1) take effect immediately for
  // entries that were cached before the detection list was broadened. We OR
  // with the cached values so we only ever lift flags, never lower them.
  const archList = cached?.architectures ? safeParseArray(cached.architectures) : [];
  const archHint = archList[0] || '';
  const fallback = detectThinkingSupportFromArch(archHint, modelId);

  if (!cached) {
    return fallback.supportsThinkingToggle ? fallback : null;
  }

  return {
    emitsThinkBlocks: cached.emitsThinkBlocks || fallback.emitsThinkBlocks,
    supportsThinkingToggle: cached.supportsThinkingToggle || fallback.supportsThinkingToggle,
  };
}

function safeParseArray(s: string): string[] {
  try {
    const parsed = JSON.parse(s);
    return Array.isArray(parsed) ? parsed : [];
  } catch {
    return [];
  }
}

// ── Performance history (per-model, cross-session) ───────────────────

function rowToPerformance(row: Record<string, unknown>): CachedPerformance {
  return {
    modelId: row.model_id as string,
    totalCalls: row.total_calls as number,
    ttftCalls: row.ttft_calls as number,
    totalTtftMs: row.total_ttft_ms as number,
    perfCalls: row.perf_calls as number,
    totalTokPerSec: row.total_tok_per_sec as number,
    totalPromptTokens: row.total_prompt_tokens as number,
    totalCompletionTokens: row.total_completion_tokens as number,
    totalReasoningTokens: row.total_reasoning_tokens as number,
    firstSeenAt: row.first_seen_at as number,
    lastUsedAt: row.last_used_at as number,
  };
}

/**
 * Fetch lifetime performance stats for a single model, or null if the model
 * has never been used on this workstation.
 */
export async function getPerformance(modelId: string): Promise<CachedPerformance | null> {
  if (!modelId) return null;
  const database = await initDb();
  const stmt = database.prepare('SELECT * FROM model_performance WHERE model_id = ?');
  try {
    stmt.bind([modelId]);
    if (stmt.step()) {
      return rowToPerformance(stmt.getAsObject() as Record<string, unknown>);
    }
    return null;
  } finally {
    stmt.free();
  }
}

/**
 * Fetch all per-model performance records (used for routing and for seeding
 * the in-memory view at startup).
 */
export async function getAllPerformance(): Promise<CachedPerformance[]> {
  const database = await initDb();
  const stmt = database.prepare('SELECT * FROM model_performance ORDER BY last_used_at DESC');
  const results: CachedPerformance[] = [];
  try {
    while (stmt.step()) {
      results.push(rowToPerformance(stmt.getAsObject() as Record<string, unknown>));
    }
  } finally {
    stmt.free();
  }
  return results;
}

/**
 * Fetch workstation-wide lifetime totals: every call, every token ever
 * offloaded to local models, across every session. Used for the "Claude
 * quota saved" footer and the discover overview.
 */
export async function getLifetimeTotals(): Promise<{ totalTokens: number; totalCalls: number; modelsUsed: number; firstSeenAt: number | null }> {
  const database = await initDb();
  const stmt = database.prepare(`
    SELECT
      COALESCE(SUM(total_prompt_tokens + total_completion_tokens), 0) AS total_tokens,
      COALESCE(SUM(total_calls), 0) AS total_calls,
      COUNT(*) AS models_used,
      MIN(first_seen_at) AS first_seen_at
    FROM model_performance
  `);
  try {
    if (stmt.step()) {
      const row = stmt.getAsObject() as Record<string, unknown>;
      return {
        totalTokens: (row.total_tokens as number) || 0,
        totalCalls: (row.total_calls as number) || 0,
        modelsUsed: (row.models_used as number) || 0,
        firstSeenAt: (row.first_seen_at as number | null) ?? null,
      };
    }
    return { totalTokens: 0, totalCalls: 0, modelsUsed: 0, firstSeenAt: null };
  } finally {
    stmt.free();
  }
}

/**
 * Append a single call's usage + timing to the per-model performance record.
 * Creates the row on first use, upserts thereafter. Caller should fire-and-
 * forget — failures here must not block a tool response.
 */
export async function recordPerformance(
  modelId: string,
  opts: {
    ttftMs?: number;
    tokPerSec?: number;
    promptTokens: number;
    completionTokens: number;
    reasoningTokens?: number;
  },
): Promise<void> {
  if (!modelId) return;
  const database = await initDb();
  const now = Date.now();
  const ttftDelta = opts.ttftMs && opts.ttftMs > 0 ? opts.ttftMs : 0;
  const ttftCallDelta = ttftDelta > 0 ? 1 : 0;
  const perfDelta = opts.tokPerSec && opts.tokPerSec > 0 ? opts.tokPerSec : 0;
  const perfCallDelta = perfDelta > 0 ? 1 : 0;
  const reasoningDelta = opts.reasoningTokens ?? 0;

  const existing = await getPerformance(modelId);

  if (existing) {
    database.run(
      `UPDATE model_performance SET
        total_calls = ?,
        ttft_calls = ?,
        total_ttft_ms = ?,
        perf_calls = ?,
        total_tok_per_sec = ?,
        total_prompt_tokens = ?,
        total_completion_tokens = ?,
        total_reasoning_tokens = ?,
        last_used_at = ?
      WHERE model_id = ?`,
      [
        existing.totalCalls + 1,
        existing.ttftCalls + ttftCallDelta,
        existing.totalTtftMs + ttftDelta,
        existing.perfCalls + perfCallDelta,
        existing.totalTokPerSec + perfDelta,
        existing.totalPromptTokens + opts.promptTokens,
        existing.totalCompletionTokens + opts.completionTokens,
        existing.totalReasoningTokens + reasoningDelta,
        now,
        modelId,
      ],
    );
  } else {
    database.run(
      `INSERT INTO model_performance (
        model_id, total_calls, ttft_calls, total_ttft_ms, perf_calls, total_tok_per_sec,
        total_prompt_tokens, total_completion_tokens, total_reasoning_tokens,
        first_seen_at, last_used_at
      ) VALUES (?, 1, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [
        modelId,
        ttftCallDelta,
        ttftDelta,
        perfCallDelta,
        perfDelta,
        opts.promptTokens,
        opts.completionTokens,
        reasoningDelta,
        now,
        now,
      ],
    );
  }
  saveDb();
}

// ── Prefill sample collection (linear-fit estimator) ─────────────────
//
// A ratio-of-averages prefill estimator (totalPromptTokens / totalTtftMs)
// systematically under-predicts for inputs much larger than the historical
// mean, because small-prompt TTFT is dominated by fixed per-request overhead
// rather than per-token prefill compute. Storing individual samples and
// fitting `TTFT ≈ α + β·prompt_tokens` separates the two components.

/** Max number of samples we retain per model. Older samples are pruned on insert. */
export const PREFILL_SAMPLES_PER_MODEL = 100;

/** Minimum number of samples before the linear fit is considered reliable. */
export const PREFILL_FIT_MIN_SAMPLES = 5;

export interface PrefillSample {
  promptTokens: number;
  ttftMs: number;
  recordedAt: number;
}

/**
 * Record a single prefill observation. Caller should fire-and-forget.
 * Automatically prunes the oldest samples beyond PREFILL_SAMPLES_PER_MODEL
 * so the table doesn't grow unboundedly.
 */
export async function recordPrefillSample(
  modelId: string,
  promptTokens: number,
  ttftMs: number,
): Promise<void> {
  if (!modelId || promptTokens <= 0 || ttftMs <= 0) return;
  const database = await initDb();
  const now = Date.now();

  database.run(
    `INSERT INTO model_prefill_samples (model_id, prompt_tokens, ttft_ms, recorded_at)
     VALUES (?, ?, ?, ?)`,
    [modelId, promptTokens, ttftMs, now],
  );

  // Prune oldest samples beyond the cap for this model.
  database.run(
    `DELETE FROM model_prefill_samples
     WHERE model_id = ?
       AND id NOT IN (
         SELECT id FROM model_prefill_samples
         WHERE model_id = ?
         ORDER BY recorded_at DESC
         LIMIT ?
       )`,
    [modelId, modelId, PREFILL_SAMPLES_PER_MODEL],
  );

  saveDb();
}

/**
 * Fetch the most recent N prefill samples for a model (oldest-first so the
 * caller can fit in whichever order feels right).
 */
export async function getPrefillSamples(modelId: string, limit: number = PREFILL_SAMPLES_PER_MODEL): Promise<PrefillSample[]> {
  if (!modelId) return [];
  const database = await initDb();
  const stmt = database.prepare(
    `SELECT prompt_tokens, ttft_ms, recorded_at
     FROM model_prefill_samples
     WHERE model_id = ?
     ORDER BY recorded_at DESC
     LIMIT ?`,
  );
  const results: PrefillSample[] = [];
  try {
    stmt.bind([modelId, limit]);
    while (stmt.step()) {
      const row = stmt.getAsObject() as Record<string, unknown>;
      results.push({
        promptTokens: row.prompt_tokens as number,
        ttftMs: row.ttft_ms as number,
        recordedAt: row.recorded_at as number,
      });
    }
  } finally {
    stmt.free();
  }
  // Reverse so caller gets oldest-first (monotonic recordedAt).
  return results.reverse();
}

export interface PrefillFit {
  /** Fixed per-request overhead (intercept, ms). */
  alphaMs: number;
  /** Per-prompt-token cost (slope, ms/token). */
  betaMsPerToken: number;
  /** Coefficient of determination — how well the line fits the data. */
  r2: number;
  /** Number of samples used. */
  n: number;
}

/**
 * Ordinary-least-squares linear regression: ttft_ms ≈ α + β·prompt_tokens.
 * Returns null when there are too few samples or zero variance in the inputs
 * (e.g. every sample happened to have the same prompt size).
 */
export function fitPrefillLinear(samples: PrefillSample[]): PrefillFit | null {
  const n = samples.length;
  if (n < PREFILL_FIT_MIN_SAMPLES) return null;

  let sumX = 0, sumY = 0;
  for (const s of samples) {
    sumX += s.promptTokens;
    sumY += s.ttftMs;
  }
  const meanX = sumX / n;
  const meanY = sumY / n;

  let num = 0, denX = 0, denY = 0;
  for (const s of samples) {
    const dx = s.promptTokens - meanX;
    const dy = s.ttftMs - meanY;
    num += dx * dy;
    denX += dx * dx;
    denY += dy * dy;
  }

  // Zero variance in X — every sample was the same prompt size. Can't fit
  // a meaningful slope; caller should fall back to the simpler estimator.
  if (denX <= 0) return null;

  const beta = num / denX;
  const alpha = meanY - beta * meanX;
  // R² via sum-of-squares. Falls back to 0 when denY=0 (all-same TTFTs, rare).
  const r2 = denY > 0 ? (num * num) / (denX * denY) : 0;

  return { alphaMs: alpha, betaMsPerToken: beta, r2, n };
}
