# The craft of delegation

Wiring up a local model is the easy part. Getting good work out of one is a skill, and it's mostly *briefing* - the same skill as handing work to a capable junior who takes everything literally and can't see your screen. This page is what we've learned running real projects through houtini-lm, including a few hundred delegated calls' worth of mistakes.

## What to hand off

The test is **bounded and self-contained**: can you describe the task completely in one message, and will you know at a glance whether the result is right?

Good fits:

- Explaining or summarising code and docs you already have
- Boilerplate: test stubs, type definitions, mock data, config scaffolds
- Format conversion - JSON↔YAML, snake_case↔camelCase, table↔prose
- Commit messages, PR descriptions, docstrings
- Code review of a pasted file or two (`code_task_files` keeps the source out of your Claude context entirely)
- First-draft brainstorming, where you want volume to react to

Poor fits:

- Anything needing tool access - the local model can't read files (beyond what `code_task_files` sends it), can't search, can't run anything
- Cross-file reasoning you haven't captured in the prompt. It knows what you sent. Nothing else.
- Work faster to do than to brief. A one-line rename doesn't survive the round trip.
- Judgement calls where a plausible-but-wrong answer costs more than doing it yourself. Local models are confident. Confidence isn't accuracy.

The economics: local inference is typically 3-30× slower than a frontier model, and free. So delegation wins when tokens are bulky and the reasoning is shallow - and loses when the reasoning is the whole job.

## Brief like the model can't see anything - because it can't

Every delegation failure we've had traces back to context the model didn't have. It won't tell you it's missing something; it'll fill the gap with something invented and carry on.

- **Send complete material.** Whole functions with their imports, whole log excerpts, whole paragraphs. Never truncate and hope.
- **State the output format as a contract.** "Return only the function", "respond as a JSON array of {line, issue}", "max 5 bullets, no preamble". Small models honour explicit format contracts surprisingly well and ignore implied ones completely.
- **Use `json_schema` when you'll parse the output.** A schema-constrained response can't drift; a politely-requested one can.
- **Specific persona, briefly.** "Senior Python developer focused on error handling" - under 30 words. It steers tone and rigour more than you'd expect.
- **One task per call.** "Review this AND suggest tests AND rewrite the docstring" gets you three half-jobs.

## The verbatim-echo pattern

The single most useful trick we've found for iterating on code with a small model, learned the expensive way.

When a draft comes back nearly right, the instinct is to point at the bug: "the collision check on line 40 is wrong, fix it." Don't. A reasoning model treats that as an invitation to re-derive the whole solution - it burns hundreds of tokens rethinking, and as often as not breaks something that worked.

Instead, *you* fix the line, and send the corrected code back with: "echo this back exactly, inside a ```javascript fence." The model's job collapses from reasoning to transcription - cheap, fast, and deterministic. It feels wasteful the first time. It's the opposite: on one project this pattern (23 round trips of it) is what made a small local drafter viable at all.

## Micro-chunking on slow hardware

MCP clients time out around 60 seconds, and while houtini-lm streams keepalives that reset the clock on well-behaved clients, not every client honours them. The universal fix is chunk size: on hardware doing ~20 tok/s, a 1,100-token output is a timeout and two 550-token outputs are two comfortable calls. When in doubt, split - a 26s call and a 42s call beat one failure.

That's also the one legitimate use of tiny `max_tokens` values, which the server otherwise ignores (the 4,096 floor - see [tools.md](tools.md#the-max_tokens-floor)). Set `HOUTINI_LM_MIN_TOKENS=0` for micro-chunk sessions and the floor steps aside.

## Reasoning models: budget for the thinking you can't see

Modern local models (Qwen3, DeepSeek, Nemotron) think before they answer, and the thinking spends your token budget invisibly. We've measured a three-line haiku costing 2,200 completion tokens - 2,190 of reasoning, then the haiku. Three consequences:

1. **Never set small output caps.** The thinking eats them and you get empty output at full inference price. This is exactly why the server floors `max_tokens` at 4,096 and defaults to 25% of context.
2. **Suppress thinking when Claude's doing the orchestration.** If a frontier model designed the task, the local model shouldn't re-reason it - it should execute. houtini-lm sends the no-think toggle automatically for models it recognises; when your backend serves an alias (vLLM serving `coder-next` rather than the model's real id), detection can't fire, so set `HOUTINI_LM_THINKING=off` and it's forced on every call.
3. **Watch the reasoning ratio in `stats`.** It's the drift alarm - if the overhead climbs, your no-think config stopped landing somewhere.

## Trust, but verify - proportionally

Everything that comes back is a draft. The footer's quality flags catch the mechanical failures (truncation, upstream errors, refusals), but plausible-and-wrong is your job to catch, and the effort should match the stakes: skim a commit message, read a summary, actually run the generated tests. The one thing we'd say from experience: verification is cheap next to the tokens you didn't spend, and much cheaper than shipping the local model's confident mistake.

## A worked example

A real briefing, the shape we use daily:

```
code_task_files:
  paths: ["C:/project/src/parser.ts", "C:/project/src/parser.test.ts"]
  language: "typescript"
  task: "The tests cover the happy path only. Write 4 additional Jest tests
         covering: empty input, input over 10MB, malformed UTF-8, and
         concurrent calls. Match the existing test style. Return only the
         new test code."
```

Bounded, self-contained, format-contracted, style-anchored to material the model can see. The source never touched Claude's context, and the review of what came back took two minutes.
