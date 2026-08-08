# Setup: Ollama as an MCP server backend for Claude

Ollama is the quickest way to turn a local model into an MCP server Claude Code can delegate to. It ships an OpenAI-compatible API on port 11434, houtini-lm detects it automatically, and the whole setup is two commands. This page covers the install, the config, and the three Ollama-specific behaviours that catch people out.

> Prefer a desktop app with a built-in model browser? See [SETUP-LMSTUDIO.md](./SETUP-LMSTUDIO.md).
> Need throughput, parallel agents or long context? See [SETUP-VLLM.md](./SETUP-VLLM.md).

## 1. Install Ollama and pull a model

Native install (macOS, Windows, Linux) from [ollama.com](https://ollama.com), then:

```bash
ollama pull qwen2.5-coder:32b
```

Or in Docker, if you have an NVIDIA GPU and the container toolkit installed:

```bash
docker run -d --gpus=all -v ollama:/root/.ollama -p 11434:11434 --name ollama ollama/ollama
docker exec -it ollama ollama pull qwen2.5-coder:32b
```

> **Docker cannot reach an Apple Silicon GPU.** Metal isn't exposed to containers, so on a Mac the Docker route runs on CPU and will be slow enough to feel broken. Install natively there.

Model sizing, and which ones are worth delegating to, is in [GETTING-STARTED.md](./GETTING-STARTED.md).

## 2. Point houtini-lm at it

Ollama serves on **port 11434**. Pass the host and port only — houtini-lm appends the API paths itself.

**Claude Code:**

```bash
claude mcp add houtini-lm -e HOUTINI_LM_ENDPOINT_URL=http://localhost:11434 -- npx -y @houtini/lm
```

**Claude Desktop**, in `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "houtini-lm": {
      "command": "npx",
      "args": ["-y", "@houtini/lm"],
      "env": {
        "HOUTINI_LM_ENDPOINT_URL": "http://localhost:11434"
      }
    }
  }
}
```

Restart, then ask Claude to run `discover`. You should see `Status: ONLINE` and your pulled models listed.

## 3. Verify end to end

```
Use houtini-lm discover
```

Then a real delegation:

```
Use houtini-lm chat to explain what a Bloom filter is, in two sentences
```

If `discover` reports offline, check Ollama is actually listening: `curl http://localhost:11434/api/tags` should return JSON.

## What houtini-lm does differently on Ollama

Three things are handled for you. They're worth knowing because they explain behaviour that looks odd otherwise.

**Detection uses `/api/tags`, not `/v1/models`.** Ollama's native list endpoint returns richer data than the OpenAI-compatible one — family, quantisation level, parameter size — so houtini-lm probes it first and maps the result. That's how `list_models` can tell you a model is `qwen2` family at `Q4_K_M` when the OpenAI endpoint would only give you a name.

**Every listed model reports as loaded.** Ollama loads on demand rather than keeping one model resident, so there's no meaningful loaded-vs-available split to show. houtini-lm marks everything listed as available. The practical consequence: the *first* call to a model you haven't used recently includes load time, which on a 32B can be tens of seconds. That isn't a hang.

**Reasoning arrives on a different channel.** Ollama's OpenAI-compatible endpoint streams thinking-model reasoning on `delta.reasoning`, where vLLM uses `reasoning_content` and some models emit `<think>` inline. houtini-lm reads all three and strips them, so you get the answer rather than the working out. Qwen3 on Ollama is the awkward case — it streams reasoning directly and can produce an orphan `</think>` closer with no opener, which is handled explicitly.

## Gotchas

**A model name is always required.** Ollama returns `HTTP 400: model is required` if the field is absent, where some backends infer a default. houtini-lm always sends one, but if you're testing with raw `curl` against `/v1/chat/completions`, that's the error you'll get for omitting it.

**Tags are part of the name.** `qwen2.5-coder:32b` and `qwen2.5-coder:7b` are different models to Ollama, and `HOUTINI_LM_MODEL` has to match exactly, tag included. A name without a tag resolves to `:latest`, which may not be what you pulled.

**Reasoning effort is `none`, not `low`.** Ollama documents `none` as a valid value; the generic OpenAI spec starts at `low`. houtini-lm sends the right one per backend, so this only matters if you're driving the endpoint yourself.

**Remote hosts need `OLLAMA_HOST`.** Ollama binds to localhost by default. To reach it from another machine, start it with `OLLAMA_HOST=0.0.0.0` and point `HOUTINI_LM_ENDPOINT_URL` at the box's LAN address — `http://192.168.1.50:11434`. Don't expose it to the internet; there's no auth.

**Empty responses usually mean thinking ate the budget.** If a reply comes back empty or as just a footer, see [troubleshooting.md](../manual/troubleshooting.md) — the first entry covers it. `HOUTINI_LM_THINKING=off` forces the no-think toggle when model detection can't identify a thinking model behind an alias.
