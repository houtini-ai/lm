# Changelog

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
