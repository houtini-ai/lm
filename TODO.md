# TODO

Backlog for houtini-lm. Substantive work lives as **GitHub issues** (so CI, PRs
and discussion attach to it); this file is the quick index plus anything too
small to warrant an issue.

## Resolve router aliases to real model names

**Problem.** When the endpoint is a LiteLLM router, `/v1/models` returns the
router's *aliases*, not the models behind them. On a live fleet that looks like:

```
local, gemma-a, gemma-b, deepseek-v4-flash, deepseek-v4-pro
```

None of those exist on HuggingFace, so `profileModelsAtStartup()` finds no card
for any of them and every model in `discover` / `list_models` comes back as
"No HuggingFace card found" with an empty **Best for**. The capability profiles
and task routing - the thing that makes `list_models` worth reading - are dead
weight for anyone running a router.

**The mapping already exists; we just do not read it.** LiteLLM exposes
`GET /model/info`, which returns `litellm_params.model` per alias. Verified
against a live router:

| alias | `litellm_params.model` |
|---|---|
| `local` | `hosted_vllm/qwen3.6-27b` |
| `gemma-a` | `hosted_vllm/gemma4-31b` |
| `gemma-b` | `hosted_vllm/gemma4-31b` |
| `deepseek-v4-flash` | `deepseek/deepseek-v4-flash` |
| `deepseek-v4-pro` | `deepseek/deepseek-v4-pro` |

Strip the provider prefix (`hosted_vllm/`, `deepseek/`) and what is left is a
name the existing HuggingFace lookup can already resolve. No hand-maintained
index file, and nothing to keep in sync on model download or removal - the
router is already the source of truth.

**Sketch.**

- In `listModelsRaw()` (`src/index.ts`), after the OpenAI-compatible branch,
  probe `/model/info`. A 200 with a `data[]` carrying `litellm_params` is a
  reliable LiteLLM tell - worth its own `Backend` value (`'litellm'`) so the
  provider profile can carry router-specific behaviour.
- Keep the alias as the callable `id` (it is what inference must be sent to)
  and add the resolved upstream name as a separate field, so HF enrichment has
  something real to look up while routing still targets the alias.
- Two aliases can resolve to the same upstream model (`gemma-a` / `gemma-b`
  above). Dedupe on the HF lookup, not on the alias.
- Degrade quietly: `/model/info` needs the router's API key and will 401
  without it. No key, or a non-LiteLLM endpoint, means today's behaviour -
  never a hard failure.

**Worth pairing with:** `retryOnRateLimit` is currently `false` for the
generic `openai-compat` profile, which is what a LiteLLM router matches today.
That default already cost a batch job most of its work (see the 429 note in the
project guide). A dedicated `'litellm'` backend is the natural place to fix it,
since a router fronting cloud tiers genuinely does need backoff.

**Also startup-only:** `profileModelsAtStartup()` runs once at boot. Inference
self-heals if the endpoint comes up later (`listModelsRaw()` re-runs per call,
and the backend is only cached on a *successful* probe), but the HF enrichment
does not. Re-running it lazily when the cache is empty would close that gap.

## Take huggingface_hub as a dependency — model download/management capability

**Origin:** 2026-08-10 Muse Glimmer day-one test (see local-llm
`docs/muse-glimmer-test-2026-08-10.md`). vLLM's in-container loader stalled
silently twice in anonymous HF rate-limit retries; the fix was host-side
`snapshot_download` + serving from a local path. Richard: make this a
first-class houtini-lm capability rather than ad-hoc rig scripts.

**Shape:** `download_model` / `list_local_models` tools — token-authenticated
pulls (HF_TOKEN), disk-space checks before download, resumable transfers, and
the local model store (`C:\dev\local-llm\models`) as a first-class concept the
fleet presets can reference. Makes the "anonymous throttle stalls the loader"
class of failure impossible by construction, and gives `discover`/`list_models`
a local inventory to report alongside the router view (pairs naturally with the
router-alias resolution item above — both feed richer model metadata).

Promote to a GitHub issue when picked up.

## Dual-model orchestration guidance — generator/critic as a first-class pattern

**Origin:** Richard, 2026-08-11, during the TP=2 Nemotron test. The rig runs two
simultaneous single-GPU models (fleet mode gemma-a/gemma-b, or qwen + gemma);
houtini-lm should help Claude understand WHERE and HOW to use them as a pair —
one model works, the other evaluates and suggests changes, then re-evals the
revision (generator/critic loop). Today that orchestration knowledge lives only
in the `delegate` skill's prose; making it a houtini-lm capability (e.g. a
`pair_review` tool, or `discover` advertising "these two models are up — one can
draft, one can critique") would let any session exploit the second GPU without
re-deriving the pattern. Pairs with the model-store and router-alias TODOs above.

Promote to a GitHub issue when picked up.

## Derive prompting schemas from the HF repo at download time

**Problem.** `getPromptHints()` in `src/model-cache.ts` is a hand-maintained regex table.
Any model newer than the table falls through to defaults (codeTemp 0.2, empty
outputConstraint, no thinking control), and those defaults are not neutral - for some
families they are actively wrong.

**Measured, 2026-08-12, Nemotron 3 Super 120B on a six-phase build task:**

| | phases done | output tokens | usable lines |
|---|---|---|---|
| defaults | 2 / 6 | 58,747 | 334 |
| card-derived settings | 6 / 6 | 18,481 | 1,780 |

Same model, same hardware, same prompts. 68% fewer tokens for 5x the output. The three
fixes were temperature 1.0 (not 0.3), `enable_thinking:false`, and an explicit
instruction to fence code. All three were documented in the model's own repo.

**Why we miss them.** `lookupHF()` fetches only `/api/models/{id}` (tags, config,
architectures, chat_template). It never fetches `README.md`, which is where sampling
guidance and thinking instructions live.

**Prototype:** `scripts/derive-prompt-schema.mjs <hf-id>` - working, verified against
two fleet models. Extracts sampling (with context, so "for coding" beats the first
number on the page), the reasoning-off mechanism, server parser flags, and whether the
model fences code by default. Correctly flagged Nemotron as needing an explicit fence
instruction, which was the exact failure above.

**To integrate:**
1. Extend `PromptHints` with `topP`, `reasoningOff`, `reasoningParser`, `toolParser`,
   `likelyStripsFences`.
2. Call the deriver on cache miss, before falling back to the regex table.
3. Persist to the existing SQLite cache alongside the profile.

**Two limitations found in testing, both important:**
- **Cards go stale.** The deriver returned `super_v3` as Nemotron's reasoning parser
  because that is what the card says. vLLM now ships it as `nemotron_v3` and *rejects*
  `super_v3`. Derived values must be validated against the runtime, not trusted.
- **Cards document deprecated methods alongside current ones.** Nemotron's card
  mentions both `enable_thinking` and the legacy "detailed thinking off" system prompt.
  Testing the legacy one and seeing it fail "proves" reasoning cannot be disabled, which
  is exactly the wrong turn that cost the day. The deriver flags this as `ambiguous`.

Promote to a GitHub issue when picked up.
