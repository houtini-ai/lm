# Houtini LM — Developer guide

This document covers internals: how the streaming pipeline works, how the
reasoning-model handling is wired, how the SQLite cache persists, and how
to extend the tool set. For user-facing docs — install, tool descriptions,
configuration — see [README.md](./README.md).

## Project layout

```
src/
  index.ts            MCP server — tool definitions, request handlers,
                      streaming, session + lifetime accounting, routing,
                      provider-profile registry
  model-cache.ts      SQLite (sql.js / WASM) — model profiles, thinking-
                      support detection, per-model performance history
server.json           MCP registry manifest
test.mjs              Direct-client integration tests (hits /v1 endpoints)
test-mcp-e2e.mjs      End-to-end MCP harness — spawns the built server over
                      stdio, drives real tool calls, verifies provider paths
benchmark.mjs         Throughput + savings benchmark
shakedown.mjs         End-to-end self-test — runs all 7 tools in sequence
SHAKEDOWN.md          Canonical test prompt (for running via Claude chat)
add-shebang.mjs       Post-build — prepends #!/usr/bin/env node to dist/index.js
```

## Commands

```bash
npm run build        # tsc + add-shebang
npm run dev          # tsc --watch
npm run shakedown    # end-to-end self-test — sanity-check install + benchmark
```

Integration test:

```bash
HOUTINI_LM_ENDPOINT_URL=http://host:1234 node test.mjs
```

Strict-mode TypeScript is enabled — the build must pass with zero errors.

## Streaming pipeline (the hot path)

`chatCompletionStreamingInner` in `src/index.ts` is where every inference call
runs. The moving parts, in order:

1. **`max_tokens` sizing** — if the caller didn't specify, derive 25% of the
   active model's context window. Fallback `DEFAULT_MAX_TOKENS` (16384) when
   context size is unknown.
2. **Reasoning-model gate** — branches on the current provider profile
   (`getProviderProfile().reasoningStyle`):
   - `'openrouter-field'` — send `reasoning: { exclude: true }`. OpenRouter
     normalises thinking output across Nemotron / DeepSeek R1 / Qwen3 /
     Claude-thinking / gpt-oss and returns clean text content only. Budget
     still inflated 4× (or +2000) because some upstream providers bill
     reasoning against the cap before filtering.
   - `'think-blocks'` (local) — call `getThinkingSupport(modelId)`. If true:
     set `enable_thinking: false` (Qwen3 vendor param), set
     `reasoning_effort` to a backend-appropriate minimum (`'none'` on
     LM Studio + Ollama, `'low'` on generic OpenAI-compatible), and inflate
     `max_tokens` 4× as a safety net for backends that ignore both flags
     (Gemma 4 and Qwen3 in Ollama both do). Inflation base is
     `effectiveMaxTokens` (context-aware), not the raw 16k default.
3. **Fetch POST** — `fetchWithTimeout(/v1/chat/completions, body, 30s connect)`.
4. **Prefill keep-alive timer** — `setInterval(PREFILL_KEEPALIVE_MS)` fires a
   `notifications/progress` every 10s until the first chunk arrives. Without
   this, long prefill on slow hardware hits the MCP client's ~60s request
   timeout before any token streams.
5. **Per-chunk read with split timeouts** — `timedRead` uses
   `PREFILL_TIMEOUT_MS` (180s) while `firstChunkReceived` is false, then
   switches to `READ_CHUNK_TIMEOUT_MS` (30s) for the rest. Big prefills
   legitimately take 1–2 min; mid-stream stalls should surface faster.
6. **Delta parsing** — recognises four OpenAI-vendor delta fields:
   - `delta.content` — visible text, accumulates into `content`
   - `delta.reasoning_content` — hidden reasoning (DeepSeek R1, Nemotron,
     LM Studio's "Separate reasoning_content" dev toggle). Accumulated into
     the `reasoning` buffer. **Must not be discarded** — see the fallback
     below.
   - `delta.reasoning` — same channel, Ollama's naming. Captured into the
     same `reasoning` buffer. Missing this was a long-standing bug:
     Ollama thinking models (qwen3:4b, deepseek-r1 etc.) appeared broken
     because all reasoning tokens were dropped on the floor.
   - `json.usage.completion_tokens_details.reasoning_tokens` — arrives on
     the final usage chunk when `stream_options.include_usage` is set.
7. **Strip `<think>...</think>`** — in-band reasoning blocks are stripped
   from `content` after assembly. Three shapes are handled: balanced pairs
   (GLM Flash), orphan openers (truncated responses), and orphan closers
   (Ollama Qwen3 streams reasoning directly on the content channel and
   terminates it with a bare `</think>` before the real answer).
8. **Empty-output safety nets**, tried in order:
   - `thinkStripFallback` — stripping emptied `content` but raw content had
     text. Returns raw content with a `think-strip-empty` quality flag.
   - `reasoningFallback` — `content` was never populated but
     `reasoning_content` was streamed (the Nemotron/DeepSeek-R1 case).
     Returns the raw reasoning with a `[No visible output — ...]` preamble
     and a `reasoning-only` quality flag.

The `recordUsage` function then writes session counters, updates the
in-memory lifetime mirror, and fires-and-forgets a SQLite write.

## Reasoning-model handling — the full picture

Three independent signals nudge a thinking model toward minimal-reasoning
output, with the expectation that at least one will land on any given
backend:

| Signal | How it's sent | Where it works |
|---|---|---|
| `enable_thinking: false` | Top-level body field | Qwen3 family via LM Studio |
| `reasoning_effort` | Top-level body field — backend-mapped value | LM Studio (`'none'`), Ollama (`'none'`), OpenAI & DeepSeek (`'low'`) |
| `max_tokens` inflation (4×) | Increases generation budget | Safety net — works even when the model ignores the other two |

Detection lives in `model-cache.ts` — `detectThinkingSupport` (HF-chat-template
based) and `detectThinkingSupportFromArch` (arch/id regex fallback). The two
paths OR their results. Re-applied at read time in `getThinkingSupport` so
stale cache entries from before the detection list was broadened still pick
up new flags without a manual refresh.

Families currently recognised as thinking: Gemma 4, Nemotron, DeepSeek R1,
GLM-4, gpt-oss, Qwen3 base (any `qwen3*` except coder/VL/embed variants —
the Jinja template defaults `enable_thinking=true`, which Ollama honours
regardless of the API flag), Qwen3-thinking, anything tagged `-thinking`.

## Backend detection

Probed once on first `listModelsRaw()` call, cached in
`detectedBackend: 'lmstudio' | 'ollama' | 'openai-compat' | 'openrouter'`
for the session. Inference always uses `/v1/chat/completions` (portable);
the backend flag steers enrichment (richer model metadata, reasoning
handling, attribution headers, retry policy, diagnostic labelling).

Probe order:
1. **OpenRouter short-circuit** — if `LM_BASE_URL` matches `openrouter.ai`
   or `HOUTINI_LM_PROVIDER=openrouter` is set, skip probes and go straight
   to `GET /v1/models` (which on OpenRouter already returns
   `context_length` and `architecture.input_modalities`).
2. `GET /api/v0/models` — LM Studio (richest metadata)
3. `GET /api/tags` — Ollama (native list, mapped to the `ModelInfo` shape)
4. `GET /v1/models` — generic (vLLM, DeepSeek, llama.cpp, any other
   OpenAI-compatible server)

## Provider profiles

`getProviderProfile()` is a small central registry that gates per-backend
behaviour. Keeps divergence in one place instead of scattered across the
hot path. Today it has flags for four things:

| Flag | Local (`lmstudio`/`ollama`/`openai-compat`) | `openrouter` |
|---|---|---|
| `extraHeaders` | `{}` | `HTTP-Referer`, `X-Title` for attribution |
| `serialiseInference` | `true` (single-GPU protection) | `false` (upstream handles parallelism) |
| `retryOnRateLimit` | `false` | `true` (jittered backoff, honours `Retry-After`) |
| `reasoningStyle` | `'think-blocks'` | `'openrouter-field'` |

Detection is URL-based (`openrouter.ai`) with `HOUTINI_LM_PROVIDER=openrouter`
as an explicit override for custom domains or self-hosted proxies. The
`ProviderProfile` interface lives near the top of `src/index.ts` — add flags
only when a real divergence forces one, not speculatively. Three providers
is where the abstraction proves its worth; two is still close to "a couple
of if-statements."

## SQLite cache — two tables

Database path: `~/.houtini-lm/model-cache.db`. Uses `sql.js` (pure WASM) to
avoid native dependencies.

### `model_profiles`

Populated at startup by `profileModelsAtStartup`. Each model gets looked up
on HuggingFace's free API; the card's `config.tokenizer_config.chat_template`
drives `emits_think_blocks` / `supports_thinking_toggle`. TTL 7 days, then
re-fetched.

Columns: `model_id` (PK), `hf_id`, `pipeline_tag`, `architectures`, `license`,
`downloads`, `likes`, `library_name`, `family`, `description`, `strengths`,
`weaknesses`, `best_for`, `emits_think_blocks`, `supports_thinking_toggle`,
`fetched_at`, `source`.

### `model_performance`

Accumulated every call. Used by the `stats` tool, `discover`'s lifetime
line, and the `code_task_files` pre-flight estimator.

Columns: `model_id` (PK), `total_calls`, `ttft_calls`, `total_ttft_ms`,
`perf_calls`, `total_tok_per_sec`, `total_prompt_tokens`,
`total_completion_tokens`, `total_reasoning_tokens`, `first_seen_at`,
`last_used_at`.

At server startup, `hydrateLifetimeFromDb()` copies this into the in-memory
`lifetime` mirror so footer and `discover` output stay synchronous (no async
DB call on the hot path). Writes fan out via `recordPerformance()`
fire-and-forget — a DB hiccup can never stall a tool response.

Derived stats:
- `avgTtftMs = totalTtftMs / ttftCalls`
- `avgTokPerSec = totalTokPerSec / perfCalls`
- `prefillTokPerSec ≈ (totalPromptTokens / calls) / (avgTtftSec)` —
  used by `estimatePrefill()` once `ttftCalls >= 2`

## Pre-flight token estimation (code_task_files)

Large inputs can still exceed the MCP client's ~60s request timeout during
prompt processing even with keep-alive notifications, because not every
client honours the `notifications/progress` timeout-reset (MCP spec says
"MAY"). The pre-flight estimator uses measured per-model prefill rate from
SQLite to refuse the call early with a diagnostic instead of letting it
silently hang.

Constants in `src/index.ts`:
- `PREFILL_REFUSE_THRESHOLD_SEC = 45` — estimated prefill above this is
  rejected with a structured error
- `PREFILL_WARN_THRESHOLD_SEC = 25` — emits a stderr warning but proceeds
- `DEFAULT_PREFILL_TOK_PER_SEC = 300` — conservative default when there's
  no measured data

Refusal only fires when `estimate.basis === 'measured'` (needs ≥2 TTFT
samples for the model). First-time callers never get refused — we err on
the side of letting the call run.

## Session vs lifetime accounting

| | Session | Lifetime |
|---|---|---|
| Scope | Since server process started | Since SQLite DB first created |
| Storage | `session` object in memory | `model_performance` rows + `lifetime` mirror |
| Survives Claude Desktop restart | No | Yes |
| Used by footer `this session: X · lifetime: Y` | Yes | Yes |
| Used by `discover` speed line | "session" variant | "lifetime on this workstation" variant |
| Used by `stats` tool | Totals + per-model | Totals + per-model |
| Feeds `estimatePrefill` | No | Yes (needs persistence for reliability) |

## Adding a new MCP tool

1. Add to the `TOOLS` array in `src/index.ts` — `name`, description,
   `inputSchema`. Descriptions matter: MCP clients surface them to the
   model, so specific language nudges Claude toward correct usage.
2. Add a `case '<name>':` branch to the `CallToolRequestSchema` handler.
3. If the tool calls the LLM, use `chatCompletionStreaming` so it benefits
   from the semaphore, keep-alive, reasoning handling, and footer.
4. Use `formatFooter(resp, extraLabel)` to produce the standard footer;
   `recordUsage` runs inside it and writes to both session and lifetime
   mirrors.

## Adding a new backend

The portable `/v1/chat/completions` path should work for any
OpenAI-compatible server with no changes — set `HOUTINI_LM_ENDPOINT_URL`
and `HOUTINI_LM_API_KEY` and you're likely done. Only add code when the
provider has concrete divergence from the generic path.

When you do need provider-specific behaviour:

1. **Detection** — extend the `Backend` type with the new string literal
   and teach `listModelsRaw()` to set `detectedBackend` to it. Prefer
   URL-based auto-detection with an explicit `HOUTINI_LM_PROVIDER` env var
   as override.
2. **Provider profile** — add a branch to `getProviderProfile()` for the
   new backend. Set only the flags that genuinely differ. Don't speculate
   — if you're unsure whether a flag should be on or off, leave it at the
   default and let the first real usage show you.
3. **Model listing** — if the server has a richer native endpoint worth
   preferring (like LM Studio's `/api/v0/models`), add a probe branch to
   `listModelsRaw()` above the generic `/v1/models` fallback. Map the
   response shape to `ModelInfo` inline.
4. **`reasoning_effort` values** — if the backend accepts a different
   set of values, update `getReasoningEffortValue()`. An unsupported value
   is often a 400 error rather than a silent fallback, so prefer omitting
   the field to sending a guess.
5. **Capabilities metadata mapping** — if the native list format doesn't
   fit `ModelInfo`, map it in the probe function (see the Ollama
   `/api/tags` branch for an example).
6. **Smoke-test** — run `test-mcp-e2e.mjs` against the new endpoint and
   confirm the expected profile path fires by grepping the stderr log.

## Releasing

1. Bump version in **three places**: `package.json`, `server.json`, and the
   `new Server({name, version})` call in `src/index.ts`. Keep them in sync.
2. Add a CHANGELOG entry under `## [X.Y.Z] - YYYY-MM-DD`.
3. `npm run build` — must pass cleanly.
4. `npm run shakedown` — smoke-test against a live local endpoint.
5. If the release touches provider-profile code, streaming, model routing,
   or anything in the hot path, also run `test-mcp-e2e.mjs` against
   **both** a local endpoint (LM Studio / Ollama) and OpenRouter — the
   profile branches are gated separately. See the testing matrix above.
6. Commit `v{X.Y.Z}: short description` (version-prefixed for releases).
7. Push and merge to `main`.
8. `npm publish` (requires 2FA — run manually, not via automation).

The `prepublishOnly` hook runs the build automatically. Use
`npm pack --dry-run` to preview the tarball contents before shipping.

## Gotchas

- **stdout is sacred.** Anything via `console.log()` will corrupt the MCP
  stdio transport. Use `process.stderr.write()` for every debug / log
  output.
- **Version in three places** — easy to forget one. `grep -r '"2.10.0"'`
  to find everything on a bump.
- **Windows commit messages** — use HEREDOC syntax for multi-line messages;
  cmd.exe doesn't like single quotes in `-m`.
- **Model loading is slow** (minutes on cold start). Never try to JIT-load
  a model — MCP has a ~60s timeout. The routing layer suggests better
  models instead.
- **sql.js is WASM, by design.** Zero native deps, works everywhere. Don't
  swap for `better-sqlite3` — node-gyp is a footgun for npm-installable
  MCP servers.
- **`completion_tokens_details.reasoning_tokens`** arrives only on the
  final usage chunk — you must set `stream_options.include_usage: true` to
  get it. We do.

## Testing

Four independent test harnesses, each with a different scope:

- **`test.mjs`** — **direct-client** integration test. Hits the provider's
  `/v1/*` endpoints without going through the MCP server. Good for
  regression-checking changes to streaming / parsing and for confirming a
  new provider speaks OpenAI protocol at all. Honours
  `HOUTINI_LM_ENDPOINT_URL` / `HOUTINI_LM_API_KEY` (plus legacy
  `LM_STUDIO_*` / `LM_PASSWORD` / `OPENROUTER_API_KEY`).
- **`test-mcp-e2e.mjs`** — **end-to-end MCP** test. Spawns the built server
  over stdio and drives real tool calls (`list_models`, `chat`, parallel
  requests, optional `model` pin). This is the one that verifies
  provider-profile paths fire correctly — grep the stderr log for
  `OpenRouter model …: reasoning.exclude=true` to confirm the OpenRouter
  branch took over. Set `PIN_MODEL=<id>` to also test the per-call model
  override.
- **`benchmark.mjs`** — throughput and savings benchmark, ad-hoc.
- **`shakedown.mjs`** (`npm run shakedown`) — the canonical self-test.
  Runs all 7 tools end-to-end and prints a summary table with TTFT, tok/s,
  token counts, and reasoning-token split per call. Use this to verify an
  install or post-release.

The conversational equivalent lives in [SHAKEDOWN.md](./SHAKEDOWN.md) —
paste it into a Claude session with houtini-lm attached and Claude drives
the sequence, evaluating output quality along the way.

### Testing matrix for provider changes

When you touch provider-profile code, run the E2E harness against **both**
a local and a remote endpoint before shipping. The two paths are gated by
different profile flags and a local-only test won't catch regressions on
the OpenRouter branch (and vice-versa):

```bash
# Local (LM Studio / Ollama / anything serialised)
HOUTINI_LM_ENDPOINT_URL=http://localhost:1234 node test-mcp-e2e.mjs

# Remote (OpenRouter — no semaphore, reasoning.exclude, retry policy)
HOUTINI_LM_ENDPOINT_URL=https://openrouter.ai/api \
  HOUTINI_LM_API_KEY=sk-or-v1-... \
  PIN_MODEL=nvidia/nemotron-3-nano-30b-a3b:free \
  node test-mcp-e2e.mjs
```

## Quality-signal flags reference

Flags that can appear on a response footer (`Quality: ...` line):

| Flag | Meaning |
|---|---|
| `TRUNCATED` | Soft timeout or chunk timeout — partial result returned |
| `PREFILL-STALL` | Timeout fired before ANY chunk arrived. Input probably too large for this model/hardware. |
| `think-blocks-stripped` | Raw content had `<think>` blocks; stripped before returning |
| `think-strip-empty` | Stripping emptied the content; returning raw reasoning as fallback |
| `reasoning-only` | No `delta.content` at all; returning `delta.reasoning_content` as fallback. Usually means `reasoning_effort` is being ignored — check stderr. |
| `tokens-estimated` | `usage` object missing from stream; token count estimated from content length |
| `hit-max-tokens` | `finish_reason: 'length'` — generation hit the `max_tokens` cap |

Multiple flags can appear on a single response.
