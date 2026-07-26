# TODO

Backlog for houtini-lm. The substantive nice-to-haves now live as **GitHub
issues** (so CI, PRs, and discussion attach to them); this file is a quick index
plus anything too small to warrant an issue.

## Tracked as issues

| # | Item | Notes |
|---|------|-------|
| #15 | Extra sampling params | ✅ shipped in 3.1.0 (seed/stop/top_p/top_k/penalties) |
| #16 | Per-call telemetry | Partial: `cached_tokens` + `content_filter` shipped; per-call events table still open |
| #17 | Vision / VLM support | Accept image content parts, route to a loaded vision model. Needs testing against a real VLM |
| #18 | System-prompt hardening | Safe core shipped; per-family constraint A/B tuning needs live models |
| #20 | Security tail | Forgeable-footer trust boundary (wants MCP `structuredContent`); TOCTOU note |
| #22 | Correctness tail | `getReasoningEffortValue` tradeoff; unbounded body-read deadline |

## Scoped, ready to promote to an issue

- **CLI mode** — run houtini-lm as a plain command, not just an MCP server, so an
  orchestrator can drive the fleet from a terminal with no ~60s MCP tool-call ceiling
  (reasoning-model calls exceed it) and no duplicated logic. Design in
  [`docs/CLI-MODE.md`](docs/CLI-MODE.md): extract the CallTool switch into a shared
  `handleToolCall()`, branch the entry on a recognised subcommand, keep the no-args
  MCP launch. Obsoletes the `fleet.mjs` stopgap in `local-llm`.

## Done

- **Savings telemetry** — the response footer now shows cumulative Claude-quota
  saved per session and lifetime, plus per-model TTFT / tok/s. (Was the original
  open item in this file.)

## Notes on direction

- Persistence is `node:sqlite` (Node ≥ 22.5), WAL, cross-process safe — see DEVELOPER.md.
- This repo is the **MCP bridge** (`@houtini/lm`) between Claude and any
  OpenAI-compatible endpoint. The separate vLLM serving project is a different
  codebase — keep references here to the MCP server only.
