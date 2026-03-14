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

// ── Prompt hints ─────────────────────────────────────────────────────
// Per-family guidance on how to get the best output from each model.
// Used by the routing layer to shape system prompts and parameters.

export interface PromptHints {
  /** Preferred temperature range for this model family */
  codeTemp: number;
  chatTemp: number;
  /** Extra system prompt suffix to constrain output format */
  outputConstraint: string;
  /** Whether this model emits <think> blocks that need stripping */
  emitsThinkBlocks: boolean;
  /** Task types this model excels at (for routing) */
  bestTaskTypes: ('code' | 'chat' | 'analysis' | 'embedding')[];
}

const PROMPT_HINTS: { pattern: RegExp; hints: PromptHints }[] = [
  {
    pattern: /glm[- ]?4/i,
    hints: {
      codeTemp: 0.1,
      chatTemp: 0.3,
      outputConstraint: 'Respond with ONLY the requested output. No step-by-step reasoning. No numbered analysis. No preamble. Go straight to the answer.',
      emitsThinkBlocks: true,
      bestTaskTypes: ['chat', 'analysis'],
    },
  },
  {
    pattern: /qwen3.*coder|qwen.*coder/i,
    hints: {
      codeTemp: 0.1,
      chatTemp: 0.3,
      outputConstraint: 'Be direct. Output only what was asked for.',
      emitsThinkBlocks: true,
      bestTaskTypes: ['code'],
    },
  },
  {
    pattern: /qwen3(?!.*coder)(?!.*vl)/i,
    hints: {
      codeTemp: 0.2,
      chatTemp: 0.3,
      outputConstraint: 'Be direct. Output only what was asked for.',
      emitsThinkBlocks: true,
      bestTaskTypes: ['chat', 'analysis', 'code'],
    },
  },
  {
    pattern: /llama[- ]?3/i,
    hints: {
      codeTemp: 0.2,
      chatTemp: 0.4,
      outputConstraint: '',
      emitsThinkBlocks: false,
      bestTaskTypes: ['chat', 'code', 'analysis'],
    },
  },
  {
    pattern: /nemotron/i,
    hints: {
      codeTemp: 0.1,
      chatTemp: 0.3,
      outputConstraint: '',
      emitsThinkBlocks: true,
      bestTaskTypes: ['analysis', 'code'],
    },
  },
  {
    pattern: /granite/i,
    hints: {
      codeTemp: 0.2,
      chatTemp: 0.3,
      outputConstraint: '',
      emitsThinkBlocks: false,
      bestTaskTypes: ['code', 'chat'],
    },
  },
  {
    pattern: /gpt[- ]?oss/i,
    hints: {
      codeTemp: 0.2,
      chatTemp: 0.4,
      outputConstraint: '',
      emitsThinkBlocks: false,
      bestTaskTypes: ['chat', 'code', 'analysis'],
    },
  },
  {
    pattern: /nomic.*embed|embed.*nomic/i,
    hints: {
      codeTemp: 0,
      chatTemp: 0,
      outputConstraint: '',
      emitsThinkBlocks: false,
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
    emitsThinkBlocks: false,
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
      fetched_at INTEGER NOT NULL,
      source TEXT NOT NULL DEFAULT 'huggingface'
    )
  `);

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
  stmt.bind([modelId]);

  if (stmt.step()) {
    const row = stmt.getAsObject() as Record<string, unknown>;
    stmt.free();
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
      fetchedAt: row.fetched_at as number,
      source: row.source as 'huggingface' | 'static' | 'inferred',
    };
  }
  stmt.free();
  return null;
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
      family, description, strengths, weaknesses, best_for, fetched_at, source)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
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
    [key: string]: unknown;
  };
  cardData?: {
    license?: string;
    language?: string | string[];
    [key: string]: unknown;
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

  return {
    family,
    description,
    strengths: JSON.stringify(strengths),
    weaknesses: JSON.stringify(weaknesses),
    bestFor: JSON.stringify(bestFor),
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
          fetchedAt: Date.now(),
          source: 'huggingface',
        }, true);
        profiledCount++;
      } else {
        // No HF match — cache a minimal profile so we don't retry
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
      fetchedAt: row.fetched_at as number,
      source: row.source as 'huggingface' | 'static' | 'inferred',
    });
  }
  stmt.free();
  return results;
}
