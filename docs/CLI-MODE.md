# Scope: `houtini-lm` CLI mode

Status: **scoped, not built.** A bit of design so this can be picked up cleanly.

## Why

houtini-lm runs as an MCP server over stdio. That's right for a human in Claude
Code — but for an *orchestrator driving the fleet from a terminal* the MCP layer
adds friction:

- **The MCP client imposes a ~60s tool-call timeout.** Reasoning models (DeepSeek,
  Kimi) routinely exceed it on real work — a live code review took **60.7s and only
  completed when run outside the MCP**; through `code_task_files` it timed out.
- **The transport is opaque from a shell.** Scripting delegation today means either
  the MCP (with its ceiling) or a hand-rolled curl that *duplicates* houtini-lm's
  logic — the no-think toggle nesting, the context-overflow retry, token sizing,
  stats. (A stopgap `fleet.mjs` in the `local-llm` repo does exactly this; CLI mode
  obsoletes it.)

A CLI mode runs the **same core logic** as a plain process: no MCP client, no 60s
ceiling (the process owns its own timeout), scriptable, and **zero logic
duplication**.

## Design

Tool dispatch is a single `switch(name)` inside the `CallToolRequestSchema` handler
(`src/index.ts`, ~L2297). Extract it into a pure function that both paths call:

```ts
async function handleToolCall(
  name: string,
  args: Record<string, unknown>,
  opts?: { progressToken?: string | number },
): Promise<{ content: { type: 'text'; text: string }[]; isError?: boolean }>
```

- **MCP** (unchanged behaviour):
  `server.setRequestHandler(CallToolRequestSchema, req =>
     handleToolCall(req.params.name, req.params.arguments ?? {},
       { progressToken: req.params._meta?.progressToken }))`
- **CLI**: parse `argv` → `handleToolCall(cmd, args)` → write `result.content[].text`
  to **stdout** → `process.exit(result.isError ? 1 : 0)`.

Entry branch (must preserve the no-args MCP launch Claude Code uses):

```ts
const CLI_CMDS = new Set(['chat','custom-prompt','code-task','code-task-files',
                          'discover','list-models','stats','embed']);
if (CLI_CMDS.has(process.argv[2])) { await runCli(); }   // CLI path
else { /* existing main(): start the MCP server on stdio */ }
```

No recognised subcommand ⇒ MCP server, exactly as today. `npx @houtini/lm` (no args)
is unchanged. The `bin` already points at `dist/index.js`, so `houtini-lm <cmd>`
works once the branch lands.

## CLI surface

`houtini-lm <command> [flags]`, prompt via trailing arg **or** stdin (for large/piped input):

| Command | Flags |
|---|---|
| `chat` | `--model --system --temp --max-tokens --json-schema <file>` + prompt |
| `custom-prompt` | `--model --system --context`(or `--context-file`)`--instruction` |
| `code-task` | `--model --language --task --code-file` |
| `code-task-files` | `--model --language --task --paths a,b,c` |
| `discover` / `list-models` / `stats` | (no args) |
| `embed` | `--model` + text or `--file` |

Global: `--endpoint`, `--api-key` (fall back to the same env vars as MCP), `--timeout`,
`--json` (emit the raw result object for machine consumption).

## Requirements

- **Reuse, don't duplicate.** CLI must go through `handleToolCall` so it inherits the
  no-think toggle, the context-overflow retry, token sizing, and stats persistence.
- **Preserve the MCP launch.** No-args / unrecognised subcommand ⇒ MCP server.
- **Streams:** result → **stdout**; footer + `[houtini-lm] …` logs → **stderr**, so
  `houtini-lm chat … > out.txt` captures only the answer.
- **Timeout:** process-owned, no 60s ceiling; generous default (~600s), `--timeout` override.
- **Exit code:** non-zero on tool error.

## Testing

- Unit: argv → args-object mapping per command (pure, no backend).
- Integration: `node dist/index.js discover` and `… chat --model local "say hi"` against
  a live endpoint — assert non-empty stdout + exit 0.
- **Regression:** `node dist/index.js` with no args still starts the MCP server.

## Out of scope / open

- Live token streaming to the terminal (first cut can buffer then print).
- Interactive REPL.
- Once shipped: delete the `fleet.mjs` stopgap in `local-llm`.
