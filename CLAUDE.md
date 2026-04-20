# Houtini LM — MCP Server for Local LLMs

MCP server that connects Claude Code to any OpenAI-compatible LLM endpoint (LM Studio, Ollama, vLLM, cloud APIs). TypeScript, ESM, published as `@houtini/lm` on npm.

## Project Structure

```
src/index.ts        Main server — tools, streaming, model routing, session tracking
src/model-cache.ts  SQLite-backed model profile cache via sql.js/WASM, HuggingFace enrichment
server.json         MCP registry manifest
test.mjs            Integration tests (hits a live OpenAI-compatible endpoint, not mocked)
benchmark.mjs       Throughput / savings benchmark script (ad hoc, not part of CI)
add-shebang.mjs     Post-build script — prepends #!/usr/bin/env node to dist/index.js
```

## Commands

- **Build:** `npm run build` (runs `tsc && node add-shebang.mjs`)
- **Dev:** `npm run dev` (tsc --watch)
- **Test:** `LM_STUDIO_URL=http://localhost:1234 node test.mjs` (requires a live LLM server)

## Verification

IMPORTANT: After any code change, always run `npm run build` to confirm TypeScript compiles cleanly. The build must pass with zero errors — strict mode is enabled.

Tests require a live LLM endpoint. Point `LM_STUDIO_URL` at whichever OpenAI-compatible server is running; the script auto-detects the loaded model when `LM_STUDIO_MODEL` is not set.

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
- **Session accounting** tracks cumulative tokens offloaded across all calls, plus per-model TTFT and tok/s (averaged via dedicated counters — `ttftCalls` and `perfCalls` — so calls without measurable perf don't skew the divisor)

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
- **Version in three places:** `package.json`, `server.json`, and the `new Server()` call in `index.ts` must stay in sync. **Always bump all three on any release** — grep for the current version to find every site.
- **Windows commit messages:** Use HEREDOC syntax for multi-line git commit messages (cmd.exe doesn't handle single quotes in `-m` well).
- **Model loading is slow:** Never attempt to JIT-load models — it takes minutes and MCP has a ~60s timeout. The routing layer suggests better models instead.
- **sql.js is WASM:** Zero native deps intentionally — no node-gyp, works everywhere. Don't swap for better-sqlite3.

## Releasing

1. Bump the version in **all three** places: `package.json`, `server.json`, and the `new Server()` call in `index.ts`.
2. Add a CHANGELOG entry under a new `## [X.Y.Z] - YYYY-MM-DD` heading.
3. `npm run build` — must pass cleanly.
4. Commit with `v{X.Y.Z}: Short description` (use HEREDOC on Windows).
5. Push and open/merge the PR to `main`.

### Publishing to npm (user-driven)

`npm publish` requires 2FA on this account, so Claude cannot run it end-to-end. When a release is merged to `main` and ready to ship, prepare the repo through step 5 above and then hand the terminal command back to the user:

```
npm publish
```

The `prepublishOnly` hook runs the build, so there's nothing to prepare beyond the steps above. Run `npm pack --dry-run` beforehand if you want to sanity-check what will be shipped in the tarball.

## Git

- Branch: `main`
- Remote: `houtini-ai/lm` on GitHub
- Commit style: `v2.10.0: Short description` (version-prefixed for releases; lowercase conventional commits — `fix:`, `feat:`, `docs:`, `chore:` — for everything else)
