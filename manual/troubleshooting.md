# Troubleshooting

Symptoms first, because that's what you've got. Each entry: what you're seeing, what's actually happening, what to do. Most of these we've hit ourselves - several are the reason a given fix exists in the codebase at all.

## The response is empty, or just a footer

**Usually: a thinking model spent the whole reply reasoning.** The model produced output, but all of it was `<think>` content (or landed in the backend's `reasoning_content` field) and there was nothing left after stripping. The footer flags `think-strip-empty` when the server had to fall back.

Three fixes, in order:

1. Upgrade - v3.2.1 fixed the big one: vLLM only honours the no-think toggle when it's nested inside `chat_template_kwargs`, and older versions sent it top-level, where vLLM silently ignored it.
2. If your backend serves the model under an alias (`coder-next` instead of the real Qwen id), detection can't recognise it as a thinking model. Set `HOUTINI_LM_THINKING=off` to force no-think on every call.
3. If you set a small `max_tokens` yourself with `HOUTINI_LM_MIN_TOKENS=0` active, the thinking ate your budget before any visible output. Remove the cap.

## Timeouts - the call dies around a minute

**The MCP client's ~60s request timeout, not the server's.** houtini-lm streams progress notifications from the moment the call is acknowledged - per-chunk during generation, heartbeats every 10s during prefill, even before the backend's HTTP headers arrive - and clients that honour `resetTimeoutOnProgress` (Claude Desktop does) will happily sit through multi-minute calls. Clients that ignore the keepalives will kill the request at their timeout regardless of what the server does.

If your client is the ignoring kind: split the work into smaller calls ([micro-chunking](delegation.md#micro-chunking-on-slow-hardware)), or trim the input. The `code_task_files` pre-flight estimator exists precisely to refuse calls that would die this death - a refusal with a diagnostic beats sixty silent seconds and an error.

## code_task_files refuses with "estimated prefill time exceeds the ~60s MCP client timeout"

**The estimator thinks your hardware can't prefill this input in time.** It learns from measured (prompt_tokens, TTFT) pairs per model, weights recent samples over stale ones, and only refuses on a fit it trusts (R² ≥ 0.5).

- If the input genuinely is big: split the file list, or trim the largest file. The diagnostic tells you the estimated tokens and seconds.
- If you've just changed your backend's performance settings (or moved to faster hardware), a few successful smaller calls teach it the new reality quickly - the recency weighting means stale slow samples wash out within about half a dozen calls.
- If it keeps refusing something you know your machine can handle, that's a bug worth reporting with the diagnostic text.

## 400 errors about context length from vLLM

**Strict backends reject `prompt + max_tokens > context` instead of clamping.** houtini-lm caps its budgets to the context window it's told about - but when a proxy (a LiteLLM router, say) advertises a generic window over a model actually loaded smaller, the arithmetic is right and the premise is wrong. Since v3.2.3 the server parses the *real* limit out of the backend's own error message and retries once with a corrected budget, so you should only ever see this fail if the retry also fails. If it does, check what the model is actually loaded with (`--max-model-len` on vLLM) versus what your proxy claims.

## Responses are slow, and the token counts look inflated

Look at the footer: `107→2229 tokens` on a short answer means ~2,100 tokens of hidden reasoning. That's inference time you're paying wall-clock for. Fix the thinking configuration (first entry above) and both the speed and the counts come right. `stats` tracks the reasoning-token ratio over time - low single-digit percentages mean suppression is working.

## Everything queues - parallel calls stack up

**Serialisation is on by default,** in-process and cross-process (an advisory file lock), because most local backends hold one model on one GPU and interleaved requests just thrash it. If your backend batches properly - vLLM, TGI, SGLang - set `HOUTINI_LM_SERIALISE=0` and let it. `HOUTINI_LM_CROSS_PROCESS_LOCK=0` disables just the file lock if you want in-process politeness only.

## discover says the endpoint is offline

- The URL is the **base**, no `/v1` - houtini-lm appends it. `http://localhost:8000`, not `http://localhost:8000/v1`.
- vLLM takes minutes to load a model; the port accepts connections before `/v1/models` answers. Wait for the model-loaded log line.
- On LM Studio, the server has to be started (Developer tab) - the app running isn't the server running.

## embed fails

The backend needs an actual embedding model loaded. A chat model doesn't serve `/v1/embeddings`, and single-model servers (typical vLLM) can't hold both - this is expected, not broken. Run embeddings on a backend that has one loaded, or skip the tool.

## The model gives mangled or truncated-feeling output on big inputs

Check the model's real context window in `discover`, not the family's advertised one - a 128k-family model loaded at 32k on a small GPU is a 32k model, and everything past the window is silently gone from its view. The dynamic output budget follows the *loaded* window, but your prompt still has to fit in what's left.

## Stats look wrong after switching backends

Per-model stats key on the model id the backend reports. Serve the same weights under two ids (or through a router that renames them) and you get two histories. Cosmetic, but worth knowing before you conclude the model got slower - check which id the footer names.

## Where to look when none of this fits

The server logs everything interesting to **stderr** (stdout is the MCP transport and stays clean - any log line you see mixed into responses is a bug, report it). In Claude Desktop, the MCP log files capture stderr per server: look for `[houtini-lm]` lines - budget overrides, thinking-mode decisions, retry attempts and lock waits are all narrated there. Failing that, the [issues page](https://github.com/houtini-ai/houtini-lm/issues) - a footer, the stderr lines, and your backend's version is usually enough to diagnose anything.
