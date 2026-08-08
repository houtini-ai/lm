# vLLM backend — integration notes and caveats

The local model now runs on vLLM in Docker (dual RTX 4090 48GB rig, `C:\dev\local-llm\vllm`), replacing LM Studio. These are the verified behaviours houtini-lm must account for — the "caveats" for the current version, and requirements for the optimised future version.

## Connection

As of 2026-07-23 houtini-lm no longer talks to vLLM directly — it points at a **LiteLLM router** (`C:\dev\local-llm\litellm`, Docker, port 4000) that fronts the whole fleet behind one OpenAI-compatible endpoint. This unlocks per-call model selection across local *and* cheap API tiers, which a single vLLM endpoint can't do.

- Endpoint: `http://127.0.0.1:4000` (set `HOUTINI_LM_ENDPOINT_URL`). Use `127.0.0.1`, not `localhost` — WSL2 mirrored networking resolves `localhost` to IPv6 and times out.
- Auth: the router requires a master key. Set `HOUTINI_LM_API_KEY` to the value of `LITELLM_MASTER_KEY` in `C:\dev\local-llm\litellm\.env`.
- Model names are now **router-level aliases**, selectable per call via the `model` param (all houtini-lm tools accept it):

| Tier | `model` value | Cost | Notes |
|---|---|---|---|
| free / local | `local` | free | whatever preset vLLM currently serves (default `coder-next`); swapping the vLLM preset changes what `local` means |
| cheap API | `deepseek-v4-flash` | ~$ | reasoning model; the router defaults `max_tokens` to 64k (see Caveat 1) |
| build / heavy | `deepseek-v4-pro` | ~$ | the full DeepSeek — substantial builds, long reviews, reasoning over a large pasted corpus |

**The routing ladder** (cheapest capable tier first):

1. **`local`** — free, bounded execution: review, boilerplate, tests-from-spec, extraction, conversion. Volume costs nothing.
2. **`deepseek-v4-flash`** — cheap API, high-volume general text when local is busy.
3. **`deepseek-v4-pro`** — the build/heavy-review tier: substantial modules, long documents, reasoning over a large pasted corpus.
4. **Claude (don't delegate)** — orchestration, cross-file reasoning, tool use, anything expensive if wrong.

> **Kimi/Moonshot was removed 2026-07-23.** It hung on large non-streamed requests (a ~10k-token review returned `http=000` past 300s), while `deepseek-v4` handled the identical request in ~80s. Revisit only with streaming. DeepSeek V4 is now the API build tier.

Direct-to-vLLM still works for local-only setups; everything below about vLLM behaviour applies to the `local` alias, since the router passes straight through to it.

### The router must not strip `chat_template_kwargs`

LiteLLM's `drop_params` defaults can silently remove non-standard fields. The config sets `drop_params: false` precisely so the nested `chat_template_kwargs: {enable_thinking: false}` reaches vLLM — without it every `local` call returns blank content (the exact trap in "RESOLVED in v3.2.1" below). Verified 2026-07-23: `local` returns clean content *through the router* with the nested toggle, and empty without it. If local delegation ever goes blank again, re-test this first.

## Caveat 1 — reasoning model token budgets (the big one)

**Applies to every reasoning model** — local Qwen, and the router-fronted DeepSeek V4 (and any hosted reasoner you add, e.g. Gemini). They **think before answering**: reasoning tokens are spent *before any visible output*, and the cap counts **reasoning + answer together**.

- **A low cap returns empty `content`.** The budget is burned on reasoning and the answer never starts. HTTP 200, `finish_reason: length`, `content: ""`. Looks like a model failure; it's a budget bug. Verified twice: Qwen `max_tokens=200` → empty; **DeepSeek V4 `max_tokens=8000` → 8000 reasoning tokens, `content:""`** — the whole review sat in `reasoning_content` with nothing left to emit it.
- **The cap is a ceiling, not consumption.** Set it generous — the model stops at `finish_reason: stop` when done and only bills what it generated. Verified: `deepseek-v4-pro` with a 64k ceiling answered a one-word prompt in 35 tokens. Unused budget costs nothing.
- **Set it high once, stop thinking about it per-call.** The LiteLLM router defaults `max_tokens` to **64k** on the DeepSeek entries, so callers never pass it. On `local`, vLLM sizes to the context window and houtini-lm's `HOUTINI_LM_MIN_TOKENS` floor (4096) is inflated — but for thinking-heavy work prefer an explicit **16k–32k+**. Never rely on a provider's *unset* default: the raw `/v1/completions` endpoint defaults to **16**, and an unset cap on a direct API call can instead run unbounded until the caller times out.
- The response carries reasoning separately (`reasoning_content` / the `--reasoning-parser` field): `content` = the answer, reasoning = chain-of-thought. Don't concatenate them; expose reasoning only for debugging. If `content` is empty but `reasoning_content` is full, that's the low-cap trap above — raise the budget.

## Thinking mode is client-controllable — default it OFF for orchestrated calls

Qwen3.6's thinking can be disabled per-request via the standard vLLM passthrough:

```json
{ "chat_template_kwargs": { "enable_thinking": false } }
```

Measured on the same server, same tool-call request: **thinking=true → 135 tokens, 3.7s; thinking=false → 26 tokens, 0.8s** — identical correct structured tool call. When Claude orchestrates (Claude does the strategic reasoning, the local model executes), no-think is the right default: ~4x faster responses and far smaller token budgets needed. Expose thinking as an opt-in per call for hard standalone subtasks (tricky refactors, maths). With thinking off, the empty-content trap in Caveat 1 also largely disappears — but keep the min-tokens floor anyway for thinking-enabled calls.

## RESOLVED in v3.2.1 — vLLM thinking models returned empty content

Two causes, both fixed in source and verified end-to-end against live Qwen3-Coder-Next:

1. **Wrong param shape.** houtini-lm sent `enable_thinking:false` only at the top level (correct for LM Studio/Ollama), which vLLM's OpenAI server silently ignores — it reads the toggle from `chat_template_kwargs`. Now sent in **both** shapes. The answer no longer lands in `reasoning_content` with empty `content`.
2. **Detection gap.** houtini-lm decides whether to send the toggle by identifying the model as a thinking model from Hugging Face metadata — but vLLM serves under arbitrary aliases (e.g. `coder-next`) that resolve to nothing on HF, so a genuine thinking model looked non-thinking and the toggle-branch never ran.

**Fix for the detection gap: `HOUTINI_LM_THINKING`** (`auto` | `off` | `on`, default `auto`).
- `off` forces the no-think path for every call regardless of detection — the correct setting when Claude orchestrates and the local model only executes, and **required** for any vLLM model served under an alias.
- `auto` keeps HF-metadata detection (fine for LM Studio / Ollama where the model id is the real one).
- `on` forces thinking on.

Set it in the MCP server's `env` (Claude config) alongside `HOUTINI_LM_ENDPOINT_URL`. Regression-guarded by `test-vllm-thinking.mjs` (`npm run test:vllm`).

> Note: `HOUTINI_LM_THINKING=off` only *suppresses* thinking; it never fabricates it. for hard standalone subtasks that want the model's own reasoning, leave it `auto` and rely on detection, or run a second endpoint with thinking on.

## Caveat 2 — tool calls

- Server-side parsers translate each model's native dialect to the standard OpenAI `tool_calls` schema (per-model parser matrix in `C:\dev\local-llm\docs\vllm-setup.md`). Client needs **zero** model-specific handling — but when `tool_calls` is present, `content` is typically `null`; handle that.
- Verified working with `--tool-call-parser qwen3_xml`. With a wrong server parser the calls leak into `content` as raw XML/text — if that's ever observed, it's a *server preset* bug, not a model limitation.

## Caveat 3 — speed expectations (current version)

- Official Qwen FP8 checkpoint on Ada: measured **18.8 tok/s** decode (block-FP8 hits untuned kernels on 4090s). With thinking overhead, first visible output can take 10–20s.
- **Set generous HTTP timeouts**: a 4k-token reasoning-heavy response can take 3–5 minutes at current speed. Recommend ≥ 600s.
- AWQ INT4 + TurboQuant KV requant (in progress) targets 40–50 tok/s; MTP speculative decoding may add more. Timeouts can tighten after the tuning session — check `C:\dev\local-llm\vllm\bench-results.jsonl` for measured numbers.

## Caveat 4 — one model at a time

- vLLM loads a single model; swapping = container restart (~1–2 min): `C:\dev\local-llm\vllm\swap-model.ps1 <preset>` (no args lists presets: coding / vision / general / fast-MoE).
- `/v1/models` only reports the *loaded* model. What's on disk: `list-models.ps1`.
- During a swap the endpoint is down — houtini-lm should surface a clear "backend restarting" error rather than retry-storming.

## Design note for the optimised future version — prefix caching

The tuning plan enables vLLM prefix caching, which reuses KV for **byte-identical prompt prefixes**. To exploit it, houtini-lm should:

1. Keep system prompts **byte-stable** across calls (no timestamps, request IDs, or reordered tool schemas in the system prompt).
2. Put stable content (system prompt, tool definitions, standing context) *first*, variable content (user task, pasted code) *last*.
3. For multi-turn delegation, resend identical history prefixes verbatim.

Done right, TTFT on repeated 16k-token delegation contexts drops from seconds to near-zero — this is the single biggest UX win available for the future version.

## Routing spec (for the optimised version — "something that just knows")

The measured fleet (see `C:\dev\local-llm\docs\MODELS.md`) maps cleanly onto houtini-lm's task types:

| Task profile | Served model | Measured |
|---|---|---|
| extraction / JSON / format / translate | `lfm2.5-8b` | 200 tok/s, strip `<think>` |
| TypeScript / MCP / Workers codegen | `fable-coder-12b` | correct handlers in ~12s |
| general drafts / summaries / bulk | `qwen3.6-35b-a3b` | 133 tok/s (boot default) |
| hard debugging / review (thinking ON) | `qwen3.6-27b` | accuracy flagship |
| image input | `qwen3-vl-32b` | OCR verified |

Design: (1) static map from tool/task-type first; (2) for ambiguous calls, a sub-second LFM2.5 classification request picks the role (~50 tokens — the fleet routes the fleet); (3) single-GPU reality: routing = swap-or-settle — only trigger a swap (`vllm/swap-model.ps1`, ~2 min) when the queued work amortises it, else settle for the loaded generalist; (4) post-second-GPU: two models warm simultaneously, routing becomes free per-request. Surface the chosen model in the response footer so users can audit routing.

## Concurrency

vLLM continuous-batches natively — the LM Studio-era "one call at a time" rule can relax in the future version. Measured aggregate throughput at 4 concurrent requests is in `bench-results.jsonl`. Modest parallelism (2–4) is fine; single-stream latency degrades gracefully.
