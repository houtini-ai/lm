# @houtini/lm

[![npm version](https://img.shields.io/npm/v/@houtini/lm)](https://www.npmjs.com/package/@houtini/lm)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

MCP server that connects Claude to **any OpenAI-compatible LLM endpoint** — LM Studio, Ollama, vLLM, llama.cpp, or any remote API.

Offload routine work to a local model. Keep your Claude context window for the hard stuff.

## Why

Claude is great at orchestration and reasoning. Local models are great at bulk analysis, classification, extraction, and summarisation. This server lets Claude delegate to a local model on the fly — no API keys, no cloud round-trips, no context wasted.

**Common use cases:**

- Classify or tag hundreds of items without burning Claude tokens
- Extract structured data from long documents
- Run a second opinion on generated code
- Summarise research before Claude synthesises it

## Install

### Claude Code (recommended)

```bash
claude mcp add houtini-lm -e LM_STUDIO_URL=http://localhost:1234 -- npx -y @houtini/lm
```

### Claude Desktop

Add to `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "houtini-lm": {
      "command": "npx",
      "args": ["-y", "@houtini/lm"],
      "env": {
        "LM_STUDIO_URL": "http://localhost:1234"
      }
    }
  }
}
```

### npx (standalone)

```bash
npx @houtini/lm
```

## Configuration

Set via environment variables or in your MCP client config:

| Variable | Default | Description |
|----------|---------|-------------|
| `LM_STUDIO_URL` | `http://localhost:1234` | Base URL of the OpenAI-compatible API |
| `LM_STUDIO_MODEL` | *(auto-detect)* | Model identifier — leave blank to use whatever's loaded |
| `LM_STUDIO_PASSWORD` | *(none)* | Bearer token for authenticated endpoints |

## Tools

### `chat`

Send a message, get a response. The workhorse.

```
message (required) — what to send
system             — system prompt
temperature        — 0–2, default 0.3
max_tokens         — default 4096
```

### `custom_prompt`

Structured prompt with separate system, context, and instruction fields. Better for analysis tasks where you're passing data + instructions.

```
instruction (required) — what to do with the context
system                 — system prompt / persona
context                — data or background to analyse
temperature            — default 0.3
max_tokens             — default 4096
```

### `list_models`

Returns the models currently loaded on the LLM server.

### `health_check`

Checks connectivity. Returns response time, auth status, and loaded model count.

## Compatible endpoints

| Provider | URL | Notes |
|----------|-----|-------|
| [LM Studio](https://lmstudio.ai) | `http://localhost:1234` | Default, zero config |
| [Ollama](https://ollama.com) | `http://localhost:11434` | Use OpenAI-compatible mode |
| [vLLM](https://docs.vllm.ai) | `http://localhost:8000` | Native OpenAI API |
| [llama.cpp](https://github.com/ggml-org/llama.cpp) | `http://localhost:8080` | Server mode |
| Remote / cloud APIs | Any URL | Set `LM_STUDIO_URL` + `LM_STUDIO_PASSWORD` |

## Development

```bash
git clone https://github.com/houtini-ai/lm.git
cd lm
npm install
npm run build
```

Run the test suite against a live LLM server:

```bash
node test.mjs
```

## License

MIT
