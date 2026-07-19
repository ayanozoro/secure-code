# Guardrail Security Scanner

`guardrail` is a TypeScript CLI for hybrid static + AI security scanning of JavaScript/TypeScript codebases.

## Current Status (Completed Phases 1-4)

- **Static Analysis Engine**: Uses Semgrep CLI and custom Tree-sitter AST queries to detect Broken Access Control (IDOR) and injection vulnerabilities.
- **AI Gating & Validation**: Integrates Anthropic Claude and OpenAI-compatible models (like GPT-4o-mini or local models like Llama via Ollama/LM Studio) to analyze and filter out false positives, complete with descriptions and fix suggestions.
- **Diagnostics**: Includes a `guardrail doctor` command to check environment health (Node, Semgrep, credentials, and cache write permissions).
- **Git Integration**: Out-of-the-box pre-commit hooks via `husky` and `lint-staged` to intercept and block commits containing high/critical security issues.
- **Custom Formats**: Outputs findings in standard terminal format, GitHub Actions Workflow annotations, or schema-compliant SARIF format.
- **Benchmark Suite**: Baseline performance benchmarks against vulnerable repositories. See [Benchmark Results](file:///d:/project/secure-code/benchmarks/results.md).

## Project Structure

- `packages/core`: Core scanner engine, custom Tree-sitter AST logic, AI interfaces, and caching modules.
- `packages/cli`: Command-line interface logic, colored format printers, and doctor command.
- `benchmarks/`: Cloned target vulnerable codebases and benchmark reports.

## Prerequisites

- Node.js >= 18.0.0
- Semgrep (optional, static checks will fall back to custom rules if not present)
- Environment keys (optional): `OPENAI_API_KEY` or `ANTHROPIC_API_KEY` to enable AI validations.

## Commands

```bash
# Setup
npm install
npm run build

# Environment health check
node packages/cli/dist/index.js doctor

# Run all checks at once (Doctor, Scan, Benchmarks, and Tests)
npm run verify

# Run scans manually
node packages/cli/dist/index.js scan .
node packages/cli/dist/index.js scan --no-ai .
node packages/cli/dist/index.js scan packages/core/fixtures --format sarif -o report.sarif
```


