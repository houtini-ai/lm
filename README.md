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
- Delegate code review to a local model while Claude handles other work

## What's new in v2.1.0

- **Smarter tool descriptions** — tool descriptions now encode prompting best practices for local LLMs, so Claude automatically sends well-structured prompts (complete code, capped output tokens, explicit format instructions)
- **New `code_task` tool** — purpose-built for code analysis with an optimised system prompt and sensible defaults (temp 0.2, 500 token cap)
- **Delegation guidance** — each tool description tells Claude when to use it, what output to expect, and what to avoid (e.g. never send truncated code to a local model)

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

Delegate a bounded task to the local LLM. The workhorse for quick questions, code explanation, and pattern recognition.

```
message (required) — the task, with explicit output format instructions
system             — persona (be specific: "Senior TypeScript dev", not "helpful assistant")
temperature        — 0.1 for code, 0.3 for analysis (default), 0.5 for suggestions
max_tokens         — match to expected output: 150 for quick answers, 300 for explanations, 500 for code gen
```

**Tip:** Always send complete code — local models hallucinate details for truncated input.

### `custom_prompt`

Structured 3-part prompt with separate system, context, and instruction fields. The separation prevents context bleed in local models — better results than stuffing everything into a single message.

```
instruction (required) — what to produce (under 50 words works best)
system                 — persona, specific and under 30 words
context                — COMPLETE data to analyse (never truncated)
temperature            — 0.1 for review, 0.3 for analysis (default)
max_tokens             — 200 for bullets, 400 for detailed review, 600 for code gen
```

### `code_task`

Purpose-built for code analysis. Wraps the local LLM with an optimised code-review system prompt and low temperature (0.2).

```
code (required)     — complete source code (never truncate)
task (required)     — what to do: "Find bugs", "Explain this function", "Add error handling"
language            — "typescript", "python", "rust", etc.
max_tokens          — default 500 (200 for quick answers, 800 for code generation)
```

**The local LLM excels at:** explaining code, finding common bugs, suggesting improvements, comparing patterns, generating boilerplate.

**It struggles with:** subtle/adversarial bugs, multi-file reasoning, design tasks requiring integration.

### `list_models`

Returns the models currently loaded on the LLM server.

### `health_check`

Checks connectivity. Returns response time, auth status, and loaded model count.

## Performance guide

At typical local LLM speeds (~3-4 tokens/second on consumer hardware):

| max_tokens | Response time | Best for |
|------------|--------------|----------|
| 150 | ~45 seconds | Quick questions, classifications |
| 300 | ~100 seconds | Code explanations, summaries |
| 500 | ~170 seconds | Code review, generation |

Set `max_tokens` to match your expected output — lower values mean faster responses.

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
