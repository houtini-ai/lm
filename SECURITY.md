# Security Policy

## Supported versions

Only the latest minor version published to npm (`@houtini/lm`) receives security fixes. Upgrade before reporting.

## Reporting a vulnerability

Please **do not** open a public GitHub issue for security vulnerabilities.

Instead, use GitHub's [private vulnerability reporting](https://github.com/houtini-ai/houtini-lm/security/advisories/new) feature. If that's not available to you, email **hello@houtini.com** with the details.

Please include:

- A description of the vulnerability and its impact
- Steps to reproduce (or a minimal proof-of-concept)
- The version of `@houtini/lm` affected
- Any relevant environment details (OS, Node version, LLM endpoint)

You should expect an acknowledgement within 72 hours and a fix or mitigation plan within 14 days for confirmed issues. Credit will be given in the changelog unless you prefer to remain anonymous.

## Scope

In scope:
- The `@houtini/lm` MCP server (`src/`, published npm package)
- The SQLite model cache (`src/model-cache.ts`)

Out of scope:
- Vulnerabilities in third-party LLM endpoints (LM Studio, Ollama, vLLM, etc.) — report those upstream
- Vulnerabilities in the MCP SDK itself — report to the [MCP project](https://github.com/modelcontextprotocol)
- Issues that require physical access to the user's machine
