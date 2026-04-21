# Changelog

## [2.13.2] - 2026-04-21

### Fixed
- **Pre-fetch progress heartbeat** — streaming keepalive used to start only after the upstream LLM returned HTTP response headers. On slow backends (big prompt, heavy prefill, cold model) the POST to `/v1/chat/completions` can sit open for 30–60+ seconds before headers flush, and that window was silent — tripping MCP clients with the default 60s request timeout before any progress notification could fire. `chatCompletionStreamingInner` now sends a progress notification immediately on tool-call receipt (resetting the client clock as soon as the call is acknowledged) plus a 10s heartbeat while awaiting upstream response headers. The existing post-fetch prefill keepalive is preserved. Clients that honour `resetTimeoutOnProgress` (Claude Desktop and similar) will now survive multi-minute prefills cleanly.

## [2.13.1] - 2026-04-21

### Changed
- **`HOUTINI_LM_MODEL` is now a genuine override**, not just a routing fallback. When set, every tool call uses that model id without running through the scoring path. Previously the env var was only consulted when routing failed entirely, which meant that on OpenRouter (where all 343 models report as "loaded") the router would pick essentially at random regardless of the user's configured preference. Backwards-compatible: if the env var is unset, routing behaves exactly as before.

### Added
- **Optional `model` parameter on `chat`, `custom_prompt`, `code_task`, `code_task_files`** — lets the caller pin a specific model id per-tool-call, overriding both routing and `HOUTINI_LM_MODEL`. Especially useful on OpenRouter: pass `model: "nvidia/nemotron-3-nano-30b-a3b:free"` or `model: "moonshotai/kimi-k2.6"` directly from the MCP client. `embed` already had a `model` parameter.

## [2.13.0] - 2026-04-21

### Added
- **`HOUTINI_LM_*` env var namespace** — now that multiple providers are supported the `LM_STUDIO_*` prefix is misleading. New preferred names: `HOUTINI_LM_ENDPOINT_URL`, `HOUTINI_LM_API_KEY`, `HOUTINI_LM_MODEL`, `HOUTINI_LM_PROVIDER`, `HOUTINI_LM_CONTEXT_WINDOW`. Legacy `LM_STUDIO_URL` / `LM_STUDIO_MODEL` / `LM_STUDIO_PASSWORD` / `LM_PASSWORD` / `OPENROUTER_API_KEY` / `LM_CONTEXT_WINDOW` remain accepted indefinitely — existing configs keep working untouched.
- **OpenRouter support** — detected automatically when `LM_STUDIO_URL` contains `openrouter.ai`, or forced via `HOUTINI_LM_PROVIDER=openrouter`. Attribution headers (`HTTP-Referer`, `X-Title`) are sent per request. Auth via `LM_STUDIO_PASSWORD` / `LM_PASSWORD` / `OPENROUTER_API_KEY` (all three names accepted).
- **Provider-profile layer** — small central registry (`getProviderProfile()`) gates per-backend behaviour: extra request headers, inference serialisation, 429/5xx retry policy, and reasoning-model output handling. Keeps per-provider divergence in one place so adding Groq/Together/Fireworks later is a config change, not a scavenger hunt across the file.
- **Jittered retry-with-backoff on 429/5xx** for remote providers (`fetchWithRetry`). Honours `Retry-After` header (seconds or HTTP-date) with a 10s ceiling. Local providers are unchanged — still a single-shot fetch.
- **End-to-end MCP smoke test** (`test-mcp-e2e.mjs`) — spawns the built server over stdio and drives real tool calls. Used to validate provider paths against both LM Studio and OpenRouter without mocking.

### Changed
- **Inference semaphore is now provider-gated** — only serialises requests for local/LM-Studio/Ollama backends (where a single GPU is being contended for). Remote providers bypass the lock and can serve parallel calls, which OpenRouter and similar multi-host backends handle natively.
- **Reasoning-model handling branches on provider**. Local thinking models still get `enable_thinking:false` + `reasoning_effort` + max_tokens inflation. OpenRouter gets `reasoning: { exclude: true }` (which the provider normalises across Nemotron, DeepSeek R1, Qwen3, Claude thinking etc.) plus the same max_tokens inflation to defend against providers that bill reasoning tokens against the cap before exclude filtering.
- **Model listing short-circuits for OpenRouter** — skips LM Studio `/api/v0/models` and Ollama `/api/tags` probes and goes straight to `/v1/models`, which on OpenRouter already returns `context_length` and `architecture.input_modalities` at the richness our routing needs.
- **`test.mjs` honours `LM_PASSWORD` / `OPENROUTER_API_KEY`** for bearer auth, so the same suite can run against remote providers for smoke testing.

## [2.12.0] - 2026-04-21

### Fixed
- **Ollama `delta.reasoning` capture** — Ollama's OpenAI-compatible streaming emits reasoning on `delta.reasoning`, not `delta.reasoning_content` (which LM Studio uses). The field was silently dropped, so Ollama thinking models like `qwen3:4b` produced empty `content` with `finish_reason=length` at default `max_tokens`. Now captured identically to LM Studio's channel — routing, safety-net fallback, and the `reasoning-only` quality flag all fire for Ollama.
- **Qwen3 base models detected as thinking-capable** — `qwen3:4b`, `qwen3-8b`, `qwen3-14b-instruct` etc. ship with `enable_thinking=true` hardcoded in their Jinja template (Ollama ignores the API flag). `detectThinkingSupportFromArch()` now flags any `qwen3*` model except coder / VL / embedding variants, so `max_tokens` inflation fires on first call. Previously only `qwen3-thinking`-tagged variants were recognised.
- **Auto-inject `model` field** — Ollama returns HTTP 400 ("model is required") when the field is absent; LM Studio accepted it and picked the loaded default. Inference path now resolves the active model from the backend before sending, so either backend behaves identically when the caller omits the model.

## [2.11.1] - 2026-04-20

### Changed
- **Pre-flight estimator now uses ordinary-least-squares linear regression** over the most recent 100 `(prompt_tokens, TTFT_ms)` samples per model. Fits `TTFT ≈ α + β·prompt_tokens` so fixed per-request overhead (α) is separated from genuine per-token prefill cost (β). The previous ratio-of-averages estimator (`totalPromptTokens / totalTtftMs`) systematically under-predicted for inputs much larger than the historical mean because small-prompt TTFT is dominated by the α term. Verified against real data: a mixed-size sample set containing one 6,955-token call and six ≤230-token calls fits α=668ms, β=1.49ms/token (R²=0.999); predicts 7,000-token TTFT as 11.1s, matching the observed 11.0s within 1%. Falls back to the ratio estimator when fewer than 5 samples exist, then to a conservative default for unknown models.

### Added
- **`model_prefill_samples` SQLite table** — stores individual `(prompt_tokens, ttft_ms)` observations per model. Capped at 100 samples per model with oldest-first pruning on each insert. Written fire-and-forget alongside `model_performance` so a DB hiccup never stalls a tool response.
- **`fitPrefillLinear()`** in `model-cache.ts` — reusable OLS implementation exposed so the `shakedown.mjs` script and any future consumers can reason about prefill characteristics of the workstation.
- **Richer refuse diagnostic** — when `code_task_files` refuses a too-large input, the error message now shows whether the estimate came from the linear fit (with α, β, R², n) or the ratio fallback, so the caller can judge confidence in the refusal.

## [2.11.0] - 2026-04-20

### Added
- **`stats` MCP tool** — compact markdown dump of session + lifetime totals, per-model performance, and reasoning-token overhead. Optional `model` filter. Cheap to call repeatedly to watch the 💰 counter climb.
- **Lifetime performance persistence** — a new `model_performance` SQLite table accumulates calls, TTFT, tok/s, prompt tokens, completion tokens, and reasoning tokens across sessions. Footer now reads `this session: X · lifetime: Y`. `discover` shows both session and lifetime speed lines, with a `last used` date. Data lives in `~/.houtini-lm/model-cache.db` alongside the existing profile cache.
- **Backend detection** — startup probe distinguishes LM Studio (`/api/v0/models`), Ollama (`/api/tags`), and generic OpenAI-compatible (`/v1/models`). Surfaced in `discover` output. Inference stays on the portable `/v1/chat/completions` path regardless — detection only steers enrichment and the per-backend `reasoning_effort` mapping.
- **`delta.reasoning_content` capture** — LM Studio's "Separate reasoning_content" dev toggle, DeepSeek R1, and Nemotron stream reasoning via this vendor-extension field. Previously discarded → silent empty bodies when the model exhausted its output budget on reasoning. Now captured into a buffer and returned as a last-ditch fallback with a `reasoning-only` quality flag so the caller sees *something*.
- **Prefill keep-alive** — a timer fires `notifications/progress` every 10s while waiting for the first chunk, preventing the MCP client's ~60s request timeout from firing during long prompt processing on slow hardware with big inputs.
- **Split prefill vs mid-stream timeouts** — `PREFILL_TIMEOUT_MS` (180s) applies until the first chunk arrives; `READ_CHUNK_TIMEOUT_MS` (30s) takes over afterwards. New `PREFILL-STALL` quality flag when truncation happens before any chunk.
- **Pre-flight token estimator for `code_task_files`** — uses measured per-model prefill rate from SQLite to refuse obviously-over-budget inputs early with a concrete diagnostic (estimated prefill seconds, tokens, sample count) instead of letting them silently hang. Only fires after ≥2 measured samples — first-time callers are never refused.
- **Reasoning-token split in footer** — when `usage.completion_tokens_details.reasoning_tokens` arrives, the token block reads `prompt→total (reasoning / visible)`. Diagnoses "why is the body empty despite hit-max-tokens?" instantly.
- **`reasoning_effort` + `max_completion_tokens` in request body** — sent alongside `enable_thinking: false` and `max_tokens` for broader compatibility. `reasoning_effort` value is backend-mapped: `'none'` on LM Studio + Ollama (hardest off-switch), `'low'` on generic OpenAI-compatible.
- **`shakedown.mjs` end-to-end self-test** — runs all seven tools in sequence, prints a markdown summary with real TTFT / tok/s / token counts / reasoning-token split. Wired as `npm run shakedown`. Not shipped in the npm tarball.
- **`SHAKEDOWN.md`** — canonical natural-language test prompt for conversational test runs via Claude.
- **`DEVELOPER.md`** — internals guide: streaming pipeline, reasoning-model handling, backend detection, SQLite schema, pre-flight estimator, adding tools/backends, release process, quality-flag reference.

### Fixed
- **`reasoning_effort: 'low'` caused HTTP 400 on Nemotron via LM Studio** — the LM Studio adapter accepts `none | minimal | low | medium | high | xhigh`, and Nemotron's narrower set would reject `'low'` with a silent fallback to `'on'` (maximum reasoning — opposite of intent). Backend-mapped value (`'none'` on LM Studio) is accepted by every model variant and is the hardest off-switch available.
- **Silent empty bodies on reasoning models** (Nemotron, DeepSeek R1, LM Studio with "Separate reasoning_content") — previously `delta.reasoning_content` was tracked for progress notifications but never accumulated into a content buffer, so when the model exhausted `max_tokens` on reasoning before emitting any `delta.content`, the response was empty and no safety flag fired. Now captured and returned via `reasoningFallback` with a clear preamble and flag.
- **Thinking-model detection was Gemma-4-only** — now covers Nemotron, DeepSeek R1, GLM-4, gpt-oss, and `qwen3-thinking` / `*-thinking` patterns. Arch + id + HF chat_template signals are OR'd.
- **Stale cache masked new thinking detection** — `getThinkingSupport` now re-applies the arch/id fallback at read time, so entries cached before the detection list was broadened still pick up flags without a manual cache flush.
- **`max_tokens` inflation used wrong base** — was `DEFAULT_MAX_TOKENS` (16k), now `effectiveMaxTokens` (context-aware 25%), so inflation sizes correctly on big-context models.
- **README `code_task_files` parameter name** — was documented as `file_paths`, actual parameter is `paths`.

### Changed
- **Footer format updated** to show `this session: X · lifetime: Y` and `tokens (reasoning / visible)` splits where applicable.
- **`discover` per-model speed line** now shows session and/or lifetime variants; the "not yet benchmarked" fallback only appears for models with no prior use on the workstation.
- **`code_task_files` tool description** mentions the size ceiling and pre-flight estimator behaviour.
- **`.gitignore` / `.npmignore`** add explicit `memory/` and `MEMORY.md` entries.

## [2.10.0] - 2026-04-20

### Changed
- **Tool descriptions reframed from pitch to peer** — removed "FREE, parallel worker", "delegate generously — it costs nothing", and similar salesy framing from `chat`, `custom_prompt`, `code_task`, and `code_task_files`. Descriptions now state the honest trade (local inference is typically 3-30× slower than frontier models, but doesn't bill against the user's Claude quota) and let the caller decide task-by-task. Positions houtini-lm as a sidekick — a capable peer for bounded work — rather than a blanket offload target.
- **Session savings line promoted** — the cumulative offloaded-token line now appears on its own line below the response footer with a 💰 prefix and "Claude quota saved this session" framing, instead of being pipe-separated among six other fields. Reads as value rather than accounting.
- **`discover` connection latency relabelled** — the ms number in discover is now labelled "Connection latency (does not reflect inference speed)" to avoid the prior misreading that it measured how fast the model generates tokens.

### Added
- **Session-level sidekick instructions** — the MCP `Server` now sends an `instructions` string at initialisation that frames houtini-lm as a local LLM sidekick, states when to delegate vs when not to, and directs Claude to `discover` for model speed. Surfaced once per session by the MCP client, so it sets baseline expectations rather than relying on per-tool descriptions being re-read.
- **First-call speed benchmark** — on the first measured call per model per session, the response footer adds a prominent line (`📊 First measured call on <model>: X tok/s, Yms to first token`). No synthetic warmup — the number reflects a real task. Gives Claude honest speed data for calibrating subsequent delegation decisions.
- **`discover` surfaces measured speed** — the active model's measured tok/s and TTFT appear prominently near the top of the discover output, averaged over the session. Shows "not yet benchmarked" when no real call has run, rather than inventing a number from an artificial probe.

### Fixed
- **Streaming reader cleanup on abrupt disconnect** — the `finally` block now races `reader.cancel()` against a 500ms timer before `releaseLock()`, so abrupt client disconnects free the upstream socket sooner without blocking the tool response path. Previously `releaseLock()` alone could leave a wedged upstream connection until the per-chunk timeout fired.
- **Average TTFT denominator** — per-model `avgTtftMs` (in `discover`, the `houtini://metrics/session` resource, and the session performance block) now divides `totalTtftMs` by a dedicated `ttftCalls` counter rather than `calls`. Previously, calls that reported no TTFT still counted toward the divisor, under-reporting the average. Surfaced by the new prominent speed line in `discover`.
- **Footer no longer swallows session line when `parts` is empty** — if every other footer field is absent but the session savings line or first-call benchmark exists, the footer now renders those instead of returning an empty string.

## [2.9.0] - 2026-04-16

### Added
- **`code_task_files` tool** (#4) — accepts absolute file paths; the server reads and concatenates them server-side so source never passes through the MCP client's context window. Uses `Promise.allSettled` so one unreadable file doesn't sink the call; failures are surfaced inline.
- **Dynamic `max_tokens`** (#5) — derived from the active model's loaded context window (25%, e.g. 262K ctx → 65K output) when the caller doesn't pass an explicit budget. Falls back to 16384 when context is unknown.
- **Progress notifications during reasoning** (#5) — each streamed chunk sends a progress notification during the thinking phase too, resetting the client's 60s clock so big-input + slow-TTFT calls don't time out.
- **Thinking-model detection for gated HuggingFace repos** — including Gemma 4.

### Fixed
- **Empty response body from thinking models** (#6) — two-layer fix:
  1. For models that support thinking toggle, inflate `max_tokens` by 4× (minimum +2000) so reasoning doesn't starve content generation. Gemma 4 hardcodes `enable_thinking=true` in its Jinja template and ignores the API flag, so this inflation is the real fix.
  2. Safety net: if the `<think>` stripper still ends up with an empty `cleanContent` (MLX/GGUF quants that ignore the flag entirely), return the raw output with a `think-strip-empty` quality flag instead of an empty body + lone footer.
- **Default soft timeout** raised to 5 minutes — progress notifications reset the MCP client's 60s clock, so the soft timeout is now a safety net rather than the primary limit.

## [2.8.0] - 2026-03-18

### Added
- **Quality metadata** — every response includes structured quality signals (truncation, think-block detection, token estimation, finish reason) so Claude can make informed trust decisions about local LLM output
- **Session metrics resource** — `houtini://metrics/session` MCP resource exposes cumulative offload stats and per-model performance as JSON, enabling proactive routing feedback
- **Request semaphore** — inference calls are serialised to prevent stacked timeouts when parallel requests hit a single-model server

### Fixed
- **SQLite statement leak** in `getCachedProfile` — statement was not freed if `getAsObject()` threw (now wrapped in try/finally)
- **Unflushed SSE buffer** — the final streaming chunk (often containing usage data) could be stranded in the buffer after loop exit, causing missing token counts on truncated responses
- **Session stats on truncated responses** — token counts now estimated from content length (~4 chars/token) when the usage chunk is lost, instead of silently showing zero

## [2.7.0] - 2026-03-14

### Added
- **Model routing** — automatically picks the best loaded model for each task type (code, chat, analysis, embedding)
- **Per-model prompt hints** — temperature, output constraints, and think-block flags tuned per model family (GLM, Qwen, LLaMA, Nemotron, Granite, GPT-OSS)
- **`stream_options: { include_usage: true }`** — enables accurate tok/s measurement from SSE streams
- Model routing suggestions when a better model is downloaded but not loaded

### Changed
- `code_task` temperature now set by routing hints (e.g. 0.1 for Qwen Coder) instead of hardcoded 0.2
- `chat` and `custom_prompt` inject output constraints into system prompts for models that need them
- Perf averaging now divides by calls with actual data, not all calls
- `profileModelsAtStartup` batches DB writes (single flush instead of per-model)
- Removed unused `dirname` import from model-cache.ts
- Test suite auto-detects loaded model instead of hardcoding

### Fixed
- tok/s was always `?` because `stream_options` wasn't set
- Perf averages inflated by calls without usage data

## [2.6.0] - 2026-03-14

### Added
- **Model discovery** — loaded vs available models, context window reporting, capability profiles
- **SQLite cache** (sql.js, pure WASM) — auto-profiles models via HuggingFace API, 7-day TTL
- **Performance stats** — TTFT and tok/s measured from SSE stream timing
- **Structured output** — `json_schema` parameter for grammar-constrained JSON
- **Embeddings tool** — `/v1/embeddings` endpoint support
- **Think-block stripping** — removes `<think>` blocks from GLM, Nemotron, Qwen3
- **12 static model profiles** — Nemotron, Granite, Qwen3, LLaMA, GLM-4, GPT-OSS, and more
- Session-level token accounting across all calls

## [2.0.1] - 2026-02-23

### Changed
- Rewrote README — clearer install instructions, use cases, and tool docs

## [2.0.0] - 2026-02-23

### Changed
- **Complete rewrite** — stripped the bloated plugin/prompt architecture down to a clean ~190-line MCP server
- Replaced `@lmstudio/sdk` with plain `fetch()` to the OpenAI-compatible API
- Removed `puppeteer`, `css-tree`, `jest`, and all unused dependencies
- Updated MCP SDK from `^1.17.3` to `^1.26.0`
- Enabled TypeScript strict mode

### Removed
- Plugin system, prompt library, caching layer, security module, template engine
- All "lite" variants and their build scripts
- Diagnostic tools, test files, development docs

### Tools
- `chat` — send a message and get a response
- `custom_prompt` — structured prompt with system message, context, and instruction
- `list_models` — list models loaded in LM Studio
- `health_check` — verify connectivity
