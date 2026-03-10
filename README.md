# @houtini/lm

[![npm version](https://img.shields.io/npm/v/@houtini/lm)](https://www.npmjs.com/package/@houtini/lm)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

<p align="center">
  <a href="https://glama.ai/mcp/servers/@houtini-ai/lm">
    <img width="380" height="200" src="https://glama.ai/mcp/servers/@houtini-ai/lm/badge" alt="Houtini LM MCP server" />
  </a>
</p>

I built this because I kept leaving Claude Code running overnight on big refactors and the token bill was painful. A huge chunk of that spend goes on bounded tasks any decent model handles fine - generating boilerplate, explaining code, drafting commit messages, converting formats. Stuff that doesn't need Claude's reasoning or tool access.

Houtini LM connects Claude Code to a local LLM on your network. Claude keeps doing the hard work - architecture, planning, multi-file changes - and offloads the grunt work to your local model. Free. No rate limits. Private.

The session footer tracks everything Claude offloads, so you can watch the savings stack up.

## How it works

```
Claude Code (orchestrator)
   │
   ├─ Complex reasoning, planning, architecture → Claude API (your tokens)
   │
   └─ Bounded grunt work → houtini-lm ──HTTP/SSE──> Your local LLM (free)
       • Boilerplate & test stubs          Qwen, Llama, Mistral, DeepSeek...
       • Code review & explanations        LM Studio, Ollama, vLLM, llama.cpp
       • Commit messages & docs
       • Format conversion
       • Mock data & type definitions
```

Claude's the architect. Your local model's the drafter. Claude QAs everything.

## Quick start

### Claude Code

```bash
claude mcp add houtini-lm -- npx -y @houtini/lm
```

That's it. If LM Studio's running on `localhost:1234` (the default), Claude can start delegating straight away.

### LLM on a different machine

I've got a GPU box on my local network running Qwen 3 Coder Next in LM Studio. If you've got a similar setup, point the URL at it:

```bash
claude mcp add houtini-lm -e LM_STUDIO_URL=http://192.168.1.50:1234 -- npx -y @houtini/lm
```

### Claude Desktop

Drop this into your `claude_desktop_config.json`:

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

## What gets offloaded

**Delegate to the local model** - bounded, well-defined tasks:

| Task | Why it works locally |
|------|---------------------|
| Generate test stubs | Clear input (source), clear output (tests) |
| Explain a function | Summarisation doesn't need tool access |
| Draft commit messages | Diff in, message out |
| Code review | Paste full source, ask for bugs |
| Convert formats | JSON↔YAML, snake_case↔camelCase |
| Generate mock data | Schema in, data out |
| Write type definitions | Source in, types out |
| Brainstorm approaches | Doesn't commit to anything |

**Keep on Claude** - anything that needs reasoning, tool access, or multi-step orchestration:

- Architectural decisions
- Reading/writing files
- Running tests and interpreting results
- Multi-file refactoring plans
- Anything that needs to call other tools

The tool descriptions are written to nudge Claude into planning delegation at the start of large tasks, not just using it when it happens to think of it.

## Token tracking

Every response includes a session footer:

```
Model: qwen/qwen3-coder-next | This call: 145→248 tokens | Session: 12,450 tokens offloaded across 23 calls
```

The `discover` tool reports cumulative session stats too. Claude sees this data and (I've found) it reinforces the delegation habit throughout long-running tasks. The more it sees it's saving tokens, the more it looks for things to offload.

## Tools

### `chat`

The workhorse. Send a task, get an answer. The description includes planning triggers that nudge Claude to identify offloadable work when it's starting a big task.

| Parameter | Required | Default | What it does |
|-----------|----------|---------|-------------|
| `message` | yes | - | The task. Be specific about output format. |
| `system` | no | - | Persona - "Senior TypeScript dev" not "helpful assistant" |
| `temperature` | no | 0.3 | 0.1 for code, 0.3 for analysis, 0.7 for creative |
| `max_tokens` | no | 2048 | Lower for quick answers, higher for generation |

### `custom_prompt`

Three-part prompt: system, context, instruction. Keeping them separate prevents context bleed - consistently outperforms stuffing everything into one message, especially with local models.

| Parameter | Required | Default | What it does |
|-----------|----------|---------|-------------|
| `instruction` | yes | - | What to produce. Under 50 words works best. |
| `system` | no | - | Persona + constraints, under 30 words |
| `context` | no | - | Complete data to analyse. Never truncate. |
| `temperature` | no | 0.3 | 0.1 for review, 0.3 for analysis |
| `max_tokens` | no | 2048 | Match to expected output length |

### `code_task`

Built for code analysis. Pre-configured system prompt, locked to temperature 0.2 for focused output.

| Parameter | Required | Default | What it does |
|-----------|----------|---------|-------------|
| `code` | yes | - | Complete source code. Never truncate. |
| `task` | yes | - | "Find bugs", "Explain this", "Write tests" |
| `language` | no | - | "typescript", "python", "rust", etc. |
| `max_tokens` | no | 2048 | Match to expected output length |

### `discover`

Health check. Returns model name, context window, latency, and cumulative session stats. Call before delegating if you're not sure the LLM's available.

### `list_models`

Lists everything loaded on the LLM server with context window sizes.

## Getting good results from local models

Qwen, Llama, DeepSeek - they score brilliantly on coding benchmarks now. The gap between a good and bad result is almost always **prompt quality**, not model capability. I've spent a fair bit of time on this.

**Send complete code.** Local models hallucinate details when you give them truncated input. If a file's too large, send the relevant function - not a snippet with `...` in the middle.

**Be explicit about output format.** "Return a JSON array" or "respond in bullet points" - don't leave it open-ended. Smaller models need this.

**Set a specific persona.** "Expert Rust developer who cares about memory safety" gets noticeably better results than "helpful assistant."

**State constraints.** "No preamble", "reference line numbers", "max 5 bullet points" - tell the model what *not* to do as well as what to do.

**Include surrounding context.** For code generation, send imports, types, and function signatures - not just the function body.

**One call at a time.** If your LLM server runs a single model, parallel calls queue up and stack timeouts. Send them sequentially.

## Configuration

| Variable | Default | What it does |
|----------|---------|-------------|
| `LM_STUDIO_URL` | `http://localhost:1234` | Base URL of the OpenAI-compatible API |
| `LM_STUDIO_MODEL` | *(auto-detect)* | Model identifier - leave blank to use whatever's loaded |
| `LM_STUDIO_PASSWORD` | *(none)* | Bearer token for authenticated endpoints |
| `LM_CONTEXT_WINDOW` | `100000` | Fallback context window if the API doesn't report it |

## Compatible endpoints

Works with anything that speaks the OpenAI `/v1/chat/completions` API:

| What | URL | Notes |
|------|-----|-------|
| [LM Studio](https://lmstudio.ai) | `http://localhost:1234` | Default, zero config |
| [Ollama](https://ollama.com) | `http://localhost:11434` | Set `LM_STUDIO_URL` |
| [vLLM](https://docs.vllm.ai) | `http://localhost:8000` | Native OpenAI API |
| [llama.cpp](https://github.com/ggml-org/llama.cpp) | `http://localhost:8080` | Server mode |
| Any OpenAI-compatible API | Any URL | Set URL + password |

## Streaming and timeouts

All inference uses Server-Sent Events streaming. Tokens arrive incrementally, keeping the connection alive. If generation takes longer than 55 seconds, you get a partial result instead of a timeout error - the footer shows `⚠ TRUNCATED` when this happens.

The 55-second soft timeout exists because the MCP SDK has a hard ~60s client-side timeout. Without streaming, any response that took longer than 60 seconds just vanished. Not ideal.

## Development

```bash
git clone https://github.com/houtini-ai/lm.git
cd lm
npm install
npm run build
```

## Licence

MIT
