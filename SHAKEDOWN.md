# Houtini LM — Shakedown test prompt

This is the canonical end-to-end test for houtini-lm. There are two ways to
run it:

1. **Automated** — `npm run shakedown` runs [`shakedown.mjs`](./shakedown.mjs)
   which talks directly to your configured endpoint (LM Studio, Ollama, or any
   OpenAI-compatible host) and prints a summary table with real TTFT / tok/s /
   reasoning-token-split for each tool.

2. **Conversational via Claude / any MCP client** — copy the prompt below into
   a Claude session that has the houtini-lm MCP server attached. Claude will
   drive the seven steps one at a time, observe each footer, and write you the
   report at the end. Useful when you want a human-readable quality review, not
   just latency numbers.

Both modes exercise the same seven tools in the same order. The conversational
version additionally evaluates output quality — did the JSON conform to the
schema, are the tests usable, did cross-file review actually cross-reference.
The automated script only checks shape (valid JSON, code-like content,
cross-file mentions); it does not judge correctness.

---

## The prompt

Paste everything from the first `#` below into your MCP-enabled chat.

---

# Houtini LM shakedown

You have the houtini-lm MCP server available. I want to exercise it
end-to-end and get a read on latency, quality, routing, and the footer
metadata.

## Ground rules (non-negotiable)

- When delegating to houtini-lm, always send COMPLETE code. If a whole file is
  too large to include, send the complete function or class under review —
  never a snippet with "..." in the middle. The local LLM cannot read files
  unless you use `code_task_files` with absolute paths.
- Between each step, check the response footer. Note the model, TTFT, tok/s,
  any quality flags (think-blocks-stripped, TRUNCATED, tokens-estimated,
  reasoning-only, PREFILL-STALL), and how the 💰 "Claude quota saved"
  number climbs over the session.
- If the 📊 first-call benchmark line appears on the first measured call,
  record the tok/s figure — that's our baseline for deciding whether to
  delegate longer work.

## Steps

1. Call `discover` first. Report:
   - Is the endpoint online? What's the active model?
   - Context window size?
   - Connection latency (which is NOT inference speed)
   - Any measured speed shown? (Should say "not yet benchmarked" on a fresh
     install; returning users see lifetime stats from the SQLite cache.)

2. Call `list_models`. Report:
   - How many models are loaded vs available-but-not-loaded?
   - Does the routing suggestion look sensible for code vs chat vs embedding?

3. `chat` — low-stakes sanity check.
   Ask: "In 3 bullets, what are the main trade-offs between WebSockets and
   Server-Sent Events?" Note TTFT and final answer quality.

4. `custom_prompt` — structured review.
   Pick a real function from this codebase (paste the COMPLETE function, not
   a snippet). Use system="Senior TypeScript reviewer, focused on error
   handling and edge cases. No preamble.", context=<the full function>,
   instruction="Return a JSON array of {line, severity: low|medium|high,
   issue, suggestion}. Max 5 items." Include a json_schema to force valid
   JSON. Check: did it return valid JSON? Did severity values stay in the
   enum? Did line numbers make sense?

5. `code_task` — test stub generation.
   Paste a COMPLETE small function from this codebase (imports + full body).
   Task: "Write 3 Jest tests covering happy path, one edge case, and one
   error path. No preamble, output only the test code." Language:
   "typescript". Check: does the test compile mentally? Does it import
   what it needs?

6. `code_task_files` — multi-file review.
   Give it the ABSOLUTE paths of two related files (e.g. a module and its
   test, or two files from a single feature). Task: "Find any bug, dead
   code, or naming inconsistency. Reference filename and line number for
   each finding. Return a terse list, max 7 items." Check: does it actually
   cross-reference across files, or just review each in isolation?

7. `embed` — quick vector test.
   Embed the sentence "Large language models running locally." Report the
   dimension count and confirm the response shape.

8. Final `discover` call. Report:
   - Does measured speed now show (tok/s + TTFT averaged over the session)?
   - How does the cumulative 💰 number compare to your own token spend
     guessing at what those same tasks would have cost on Claude?

## Report format

After step 8, give me:

- A table: tool | worked? | TTFT ms | tok/s | quality flags | notes
- One honest paragraph on quality of outputs — was step 4's JSON clean?
  Were the tests in step 5 usable? Did step 6's cross-file analysis feel
  real?
- Any footguns you hit (timeout, empty response, routing surprises, model
  load state, weird flag combinations).
- Your own verdict: for which kinds of tasks in this codebase is houtini
  a genuine win, and where is it not worth the wall-clock cost?

Do NOT fabricate latency numbers. If a call fails, report the failure and
move on — no synthetic warmups, no "averaged" guesses. The only numbers
that belong in the report are the ones the footer actually emitted.
