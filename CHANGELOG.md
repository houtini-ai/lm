# Changelog

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
