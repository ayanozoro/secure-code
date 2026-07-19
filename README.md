# Secure Code

Basic TypeScript monorepo scaffold for a local security scanner.

## Layout

- `packages/core`: shared analysis engine types and SARIF helpers
- `packages/cli`: `guardrail` CLI entrypoint

## Next steps

- Wire Semgrep execution into the core engine
- Add tree-sitter-based gap checks
- Connect the Claude review layer and suppression handling
