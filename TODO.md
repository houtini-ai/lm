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
