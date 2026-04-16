# Houtini LM — MCP Server for Local LLMs

MCP server that connects Claude Code to any OpenAI-compatible LLM endpoint (LM Studio, Ollama, vLLM, cloud APIs). TypeScript, ESM, published as `@houtini/lm` on npm.

## Project Structure

```
src/index.ts        Main server — tools, streaming, model routing, session tracking
src/model-cache.ts  SQLite-backed model profile cache via sql.js/WASM, HuggingFace enrichment
server.json         MCP registry manifest
test.mjs            Integration tests (hits live LLM server, not mocked)
add-shebang.mjs     Post-build script — prepends #!/usr/bin/env node to dist/index.js
```

## Commands

- **Build:** `npm run build` (runs `tsc && node add-shebang.mjs`)
- **Dev:** `npm run dev` (tsc --watch)
- **Test:** `node test.mjs` (requires a live LLM server at LM_STUDIO_URL)
- **Publish:** `npm publish` (runs prepublishOnly → build first)

## Verification

IMPORTANT: After any code change, always run `npm run build` to confirm TypeScript compiles cleanly. The build must pass with zero errors — strict mode is enabled.

Tests require a live LLM endpoint. If hopper is available, run: `LM_STUDIO_URL=http://hopper:1234 node test.mjs`

## Architecture

- **Single server process** using `@modelcontextprotocol/sdk` with stdio transport
- **7 tools:** `chat`, `custom_prompt`, `code_task`, `code_task_files`, `embed`, `discover`, `list_models`
- **SSE streaming** for all inference. Soft timeout is 5 min — progress notifications (sent per chunk, including during the thinking phase) reset the MCP client's 60s clock, so the soft timeout is a safety net rather than the primary limit
- **Dynamic `max_tokens`** — when the caller omits `max_tokens`, `chatCompletionStreamingInner` derives it as 25% of the active model's loaded context window. Falls back to `DEFAULT_MAX_TOKENS` (16384) when context is unknown
- **Thinking-model handling** — when `getThinkingSupport()` reports a model supports the thinking toggle: (1) request body sets `enable_thinking: false`, (2) `max_tokens` is inflated to `max(requested × 4, requested + 2000)` so reasoning doesn't starve content generation (Gemma 4 hardcodes `enable_thinking=true` in its Jinja template and ignores the API flag, so the inflation is the real fix), (3) if strip still empties the response, we return raw content and flag `think-strip-empty` as a final safety net
- **Model routing** scores loaded models by task type (code/chat/analysis/embedding)
- **Per-family prompt hints** in `model-cache.ts` (`PROMPT_HINTS` array) — temperature, output constraints, think-block flags
- **Static model profiles** in `index.ts` (`MODEL_PROFILES` array) — curated descriptions for known families
- **SQLite cache** at `~/.houtini-lm/model-cache.db` — auto-profiles models via HuggingFace API at startup, 7-day TTL
- **Session accounting** tracks cumulative tokens offloaded across all calls

## Coding Conventions

- TypeScript strict mode, ES2022 target, ESM modules
- No test framework — `test.mjs` is a plain Node.js script with sequential assertions
- All fetch calls use `fetchWithTimeout()` with AbortController — never use bare `fetch()`
- Streaming responses use `timedRead()` for per-chunk timeouts
- Think-block stripping (`<think>...</think>`) happens in `chatCompletionStreaming()` after content assembly
- Error responses return `{ isError: true }` — never throw from tool handlers
- Logs go to `process.stderr.write()` — stdout is reserved for MCP stdio transport

## Gotchas

- **stdout is sacred:** Any `console.log()` will corrupt the MCP stdio transport. Use `process.stderr.write()` for all debug/log output.
- **Version in three places:** `package.json`, `server.json`, and the `new Server()` call in `index.ts` must stay in sync — grep for the current version to find them.
- **Windows commit messages:** Use HEREDOC syntax for multi-line git commit messages (cmd.exe doesn't handle single quotes in `-m` well).
- **Model loading is slow:** Never attempt to JIT-load models — it takes minutes and MCP has a ~60s timeout. The routing layer suggests better models instead.
- **sql.js is WASM:** Zero native deps intentionally — no node-gyp, works everywhere. Don't swap for better-sqlite3.
- **`nul` file in root:** Artefact from Windows, harmless — don't commit more of these.

## Deploy / Publish

1. Bump version in `package.json`, `server.json`, and `index.ts` Server constructor
2. Update `CHANGELOG.md`
3. `npm run build`
4. `git add` the changed files, commit with format: `v{X.Y.Z}: Short description of changes`
5. `npm publish`
6. Sync to hopper: `robocopy C:\mcp\houtini-lm \\hopper\d\MCP\houtini-lm /MIR /MT:4 /XD .git node_modules __pycache__ .next .venv /XF *.pyc /NFL /NP`

## Git

- Branch: `main`
- Remote: `houtini-ai/lm` on GitHub
- Commit style: `v2.7.0: Model routing, per-family prompt hints, perf fixes` (version-prefixed for releases, lowercase description for chores)
