# Secure Code

`guardrail` is a TypeScript CLI for hybrid static + AI security scanning.

## Current status (Phase 1)

- Semgrep wrapper wired through `child_process.spawn`
- OWASP Phase 1 rule subset in `packages/core/rules/semgrep/`
- Custom tree-sitter rule module for IDOR and input validation gaps
- Dedup by `(ruleId, filePath, line)`
- Suppression support via `// scanner-ignore: reason`
- SARIF output keeps suppressed findings marked with justification
- Terminal output omits suppressed findings

## Layout

- `packages/core`: scanner engine and SARIF generation
- `packages/cli`: `guardrail` command
- `packages/core/fixtures`: vulnerable sample for smoke checks

## Prerequisites

- Node.js 20+
- Semgrep available on `PATH` (if not installed, Semgrep checks are skipped and custom rules still run)

## Commands

```bash
npm install
npm run build
npm test
node packages/cli/dist/index.js scan .
node packages/cli/dist/index.js scan packages/core/fixtures --format sarif -o report.sarif
```
