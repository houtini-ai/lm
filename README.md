# @houtini/lm

[![npm version](https://img.shields.io/npm/v/@houtini/lm)](https://www.npmjs.com/package/@houtini/lm)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

An MCP server that connects Claude to any OpenAI-compatible LLM - LM Studio, Ollama, vLLM, llama.cpp, whatever you've got running locally.

The idea's simple. Claude's brilliant at orchestration and reasoning, but you're burning tokens on stuff a local model handles just fine. Boilerplate, code review, summarisation, classification - hand it off. Claude keeps working on the hard stuff while your local model chews through the grunt work. Free, parallel, no API keys.

## Quick start

### Claude Code

```bash
claude mcp add houtini-lm -- npx -y @houtini/lm
```

That's it. If LM Studio's running on `localhost:1234` (the default), Claude can start delegating straight away.

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

### LLM on a different machine

If you've got a GPU box on your network (I run mine on a separate machine called hopper), point the URL at it:

```bash
claude mcp add houtini-lm -e LM_STUDIO_URL=http://192.168.1.50:1234 -- npx -y @houtini/lm
```

## What's it good for?

Real examples you can throw at it right now.

**Explain something you just read**
```
"Explain what this function does in 2-3 sentences."
+ paste the function
```

**Second opinion on generated code**
```
"Find bugs in this TypeScript module. Return a JSON array of {line, issue, fix}."
+ paste the module
```

**Draft a commit message**
```
"Write a concise commit message for this diff. One line summary, then bullet points."
+ paste the diff
```

**Generate boilerplate**
```
"Write a Jest test file for this React component. Cover the happy path and one error case."
+ paste the component
```

**Extract structured data**
```
"Extract all API endpoints from this Express router. Return as JSON: {method, path, handler}."
+ paste the router file
```

**Translate formats**
```
"Convert this JSON config to YAML. Return only the YAML, no explanation."
+ paste the JSON
```

**Brainstorm before committing to an approach**
```
"I need to add caching to this API client. List 3 approaches with trade-offs. Be brief."
+ paste the client code
```

## Tools

### `chat`

The workhorse. Send a task, get an answer. Optional system persona if you want to steer the model's perspective.

| Parameter | Required | Default | What it does |
|-----------|----------|---------|-------------|
| `message` | yes | - | The task. Be specific about output format. |
| `system` | no | - | Persona - "Senior TypeScript dev", not "helpful assistant" |
| `temperature` | no | 0.3 | 0.1 for code, 0.3 for analysis, 0.7 for creative |
| `max_tokens` | no | 2048 | Lower for quick answers, higher for generation |

**Quick factual question:**
```json
{
  "message": "What HTTP status code means 'too many requests'? Just the number and name.",
  "max_tokens": 50
}
```

**Code explanation with persona:**
```json
{
  "message": "Explain this function. What does it do, what are the edge cases?\n\n```ts\nfunction debounce(fn, ms) { ... }\n```",
  "system": "Senior TypeScript developer"
}
```

### `custom_prompt`

Three-part prompt: system, context, instruction. Keeping them separate stops context bleed - you'll get better results than stuffing everything into one message, especially with smaller models.

| Parameter | Required | Default | What it does |
|-----------|----------|---------|-------------|
| `instruction` | yes | - | What to produce. Under 50 words works best. |
| `system` | no | - | Persona, specific and under 30 words |
| `context` | no | - | Complete data to analyse. Never truncate. |
| `temperature` | no | 0.3 | 0.1 for review, 0.3 for analysis |
| `max_tokens` | no | 2048 | Match to expected output length |

**Code review:**
```json
{
  "system": "Expert Node.js developer focused on error handling and edge cases.",
  "context": "< full source code here >",
  "instruction": "List the top 3 bugs as bullet points. For each: line number, what's wrong, how to fix it."
}
```

**Compare two implementations:**
```json
{
  "system": "Performance-focused Python developer.",
  "context": "Implementation A:\n...\n\nImplementation B:\n...",
  "instruction": "Which is faster for 10k+ items? Why? One paragraph."
}
```

### `code_task`

Built specifically for code analysis. Wraps your request with an optimised code-review system prompt and drops the temperature to 0.2 so the model stays focused.

| Parameter | Required | Default | What it does |
|-----------|----------|---------|-------------|
| `code` | yes | - | Complete source code. Never truncate. |
| `task` | yes | - | "Find bugs", "Explain this", "Write tests" |
| `language` | no | - | "typescript", "python", "rust", etc. |
| `max_tokens` | no | 2048 | Match to expected output length |

```json
{
  "code": "< full source file >",
  "task": "Find bugs and suggest improvements. Reference line numbers.",
  "language": "typescript"
}
```

### `discover`

Checks if the local LLM's online. Returns the model name, context window size, and response latency. Typically under a second, or an offline status within 5 seconds if the host isn't reachable.

No parameters. Call it before delegating if you're not sure the LLM's available.

### `list_models`

Lists everything loaded on the LLM server with context window sizes.

## How it works

```
Claude ──MCP──> houtini-lm ──HTTP/SSE──> LM Studio (or any OpenAI-compatible API)
                    │
                    ├─ Streaming: tokens arrive incrementally via SSE
                    ├─ Soft timeout: returns partial results at 55s
                    └─ Graceful failure: returns "offline" if host unreachable
```

All inference calls use Server-Sent Events streaming (since v2.3.0). In practice, this means:

- Tokens arrive as they're generated, keeping the connection alive
- If generation takes longer than 55 seconds, you get a partial result instead of a timeout error - the footer shows `⚠ TRUNCATED` when this happens
- If the host is off or unreachable, you get a clean "offline" message within 5 seconds instead of hanging

The 55-second soft timeout exists because the MCP SDK has a hard ~60s client-side timeout. Without streaming, any response that took longer than 60 seconds just vanished. Now you get whatever the model managed to generate before the deadline.

## Configuration

| Variable | Default | What it does |
|----------|---------|-------------|
| `LM_STUDIO_URL` | `http://localhost:1234` | Base URL of the OpenAI-compatible API |
| `LM_STUDIO_MODEL` | *(auto-detect)* | Model identifier - leave blank to use whatever's loaded |
| `LM_STUDIO_PASSWORD` | *(none)* | Bearer token for authenticated endpoints |
| `LM_CONTEXT_WINDOW` | `100000` | Fallback context window if the API doesn't report it |

## Getting good results

**Send complete code.** Local models hallucinate details when you give them truncated input. If a file's too large, send the relevant function - not a snippet with `...` in the middle.

**Be explicit about output format.** "Return a JSON array" or "respond in bullet points" - don't leave it open-ended. Smaller models especially need this.

**One call at a time.** If your LLM server runs a single model, parallel calls queue up and stack timeouts. Send them sequentially.

**Match max_tokens to expected output.** 200 for quick answers, 500 for explanations, 2048 for code generation. Lower values mean faster responses.

**Set a specific persona.** "Expert Rust developer who cares about memory safety" gets noticeably better results than "helpful assistant" (or no persona at all).

## Compatible endpoints

Works with anything that speaks the OpenAI `/v1/chat/completions` API:

| What | URL | Notes |
|------|-----|-------|
| [LM Studio](https://lmstudio.ai) | `http://localhost:1234` | Default, zero config |
| [Ollama](https://ollama.com) | `http://localhost:11434` | Set `LM_STUDIO_URL` |
| [vLLM](https://docs.vllm.ai) | `http://localhost:8000` | Native OpenAI API |
| [llama.cpp](https://github.com/ggml-org/llama.cpp) | `http://localhost:8080` | Server mode |
| Any OpenAI-compatible API | Any URL | Set URL + password |

## Development

```bash
git clone https://github.com/houtini-ai/lm.git
cd lm
npm install
npm run build
```

## Licence

MIT
