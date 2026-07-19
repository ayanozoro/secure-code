# guardrail Project Context

This repository builds **guardrail**, a TypeScript CLI for hybrid static + AI security scanning of JavaScript/TypeScript codebases.

## Phase 1 Scope (current delivery target)

- OWASP A03 Injection
- OWASP A01 Broken Access Control
- Input validation gaps

Out of scope for now: crypto failures, misconfiguration, SSRF/deserialization, deep secret scanning, non-JS/TS language support.

## Architecture

The core engine lives in `packages/core` and is imported by interfaces in:

- `packages/cli` (current)
- future GitHub Action
- future VS Code extension

Core flow:

1. Static analysis first (Semgrep + custom tree-sitter checks)
2. AI validation second (only for flagged/high-risk code paths)
3. Finding aggregation, suppression handling, and SARIF output

## CLI Expectations

- Command: `guardrail scan <path>`
- Non-zero exit when **high/critical** findings exist
- SARIF output support
- Inline suppression support: `// scanner-ignore: reason`

## Engineering Rules

- Keep behavior deterministic where possible.
- Prioritize low false positives.
- Reuse shared core logic from `packages/core`; avoid CLI-only analyzer logic.
- Keep changes minimal, typed, and testable.
