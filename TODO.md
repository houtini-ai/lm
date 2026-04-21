# TODO

Shared backlog for houtini-lm. Keep entries small and actionable — this file is committed so multiple agents can coordinate.

## Open

### Savings telemetry surface

Expose cumulative token/cost savings from local-LLM delegation to the user.

**Why:** The session-accounting layer already tracks cumulative offloaded tokens and per-model perf (TTFT, tok/s), but none of it is visible unless the caller inspects internal logs. Making it visible turns an invisible benefit into a quantified one — the same move wozcode-plugin makes with `/woz-savings`. Reinforces the "delegate to local model" habit.

**How to apply:**
- Add a dedicated `savings` tool (or extend `list_models` with a `session` field) that returns:
  - Cumulative prompt + completion tokens offloaded this session
  - Per-model call count, avg TTFT, avg tok/s (already tracked via `ttftCalls` / `perfCalls`)
  - Estimated cost saved vs. a reference frontier model (config-driven $/1M tokens — keep the reference model configurable via env, don't hardcode)
- Keep the math transparent in the response — show the formula / assumed rates, not just a dollar number
- No persistence across sessions in v1 — process-lifetime accounting is enough to prove the point
