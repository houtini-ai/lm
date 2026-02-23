# Changelog

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
