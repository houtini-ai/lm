# Contributing to Houtini LM

Thanks for your interest in improving this MCP server. This guide covers the practicals; for architecture and conventions, see [CLAUDE.md](./CLAUDE.md).

## Setup

```bash
git clone https://github.com/houtini-ai/houtini-lm.git
cd houtini-lm
npm install
npm run build
```

You'll need Node.js 18+ and an OpenAI-compatible LLM endpoint (LM Studio, Ollama, vLLM, etc.) running locally to test against.

## Development

```bash
npm run dev        # tsc --watch — recompiles on save
npm run build      # one-shot build (runs add-shebang.mjs afterwards)
```

All TypeScript is strict mode. Build must pass with zero errors before you open a PR.

## Testing

```bash
HOUTINI_LM_ENDPOINT_URL=http://localhost:1234 node test.mjs
```

`test.mjs` is an integration test — it hits a live LLM server and runs sequential assertions. There is no mocking layer and no unit-test framework; this is deliberate (see [CLAUDE.md](./CLAUDE.md) → *Coding Conventions*).

If you don't have a local LLM available, note that in your PR and a maintainer will run the tests before merge.

## Commit style

- Version-bump releases: `v{X.Y.Z}: Short description of changes` (e.g. `v2.9.0: code_task_files tool + think-strip safety net`)
- Chores / bug fixes without a release: `fix: <what>`, `chore: <what>`, `docs: <what>`, `feat: <what>`
- Use a HEREDOC for multi-line messages if you're on Windows — cmd.exe mangles single quotes in `-m`

## Pull requests

1. Branch from `main`.
2. Keep PRs focused — one concern per PR, small enough to review in a sitting.
3. Update [CHANGELOG.md](./CHANGELOG.md) under an `## [Unreleased]` heading if your change is user-visible.
4. Make sure `npm run build` passes — CI will check this on PR.
5. If you're touching a tool's behaviour, run `test.mjs` against a local LLM and note in the PR that you did.

## What to work on

Open issues tagged `good first issue` or `help wanted` are the easiest entry points. Bigger ideas — new tools, new endpoint adapters — are welcome; open an issue first to discuss direction before writing code.

## Questions

Open a GitHub issue. For anything security-sensitive, see [SECURITY.md](./SECURITY.md) instead.
