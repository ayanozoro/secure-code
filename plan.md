# Development Plan: guardrail – Hybrid Static + AI Security Scanner

## Goal
Create a TypeScript CLI (`guardrail`) that performs a **hybrid static + AI security scan** on JavaScript/TypeScript codebases, catching OWASP Top 10 vulnerabilities (Injection, Broken Access Control, Input Validation gaps) and outputting SARIF results with AI-driven explanations and fixes.

---

## Phase 0 – Setup & Hygiene (≤ 2 hrs)

| Task | Action |
|------|--------|
| 1 | Overwrite `CLAUDE.md` with the short-project-specific version (no legacy SaaS context). |
| 2 | `git init` at repo root. |
| 3 | `npm install` (root workspace). |
| 4 | Add `vitest` to root devDeps + `"test": "vitest"` script. |
| 5 | Verify build & test commands run cleanly. |
| 6 | Smoke-test CLI: `node packages/cli/dist/index.js scan .` → "No findings." → exit 0. |
| 7 | Initial commit (`git add . && git commit -m "initial scaffold"). |

---

## Phase 1 – Static Engine (1 week)

### 1a. Semgrep Wrapper
- Install Semgrep binary (or use `semgrep` package) and invoke via `child_process.spawn`.
- Place OWASP-subset rule-pack under `packages/core/rules/semgrep/`.
- Map Semgrep findings → `Finding` struct.

### 1b. Custom Tree-Sitter Rules
- Add `web-tree-sitter` + JS/TS grammars.
- Implement 1-2 gap rules (e.g., missing ownership check on `req.params.id` → DB query).
- Dedup findings by `(ruleId, filePath, line)`.

### 1c. Suppression Integration
- Detect `// scanner-ignore: <reason>` inline comments.
- Mark suppressed findings in SARIF while omitting them from terminal output.

**Exit Criteria**
- Scanning a known-bad fixture produces a high-severity `Finding`.
- SARIF output validates against the SARIF 2.1.0 schema.
- Suppression removes finding from terminal output.

---

## Phase 2 – AI Validation Layer (1 week)

| Step | Detail |
|------|--------|
| **Multi-Provider AI** | Support Anthropic and OpenAI-compatible APIs (Ollama, LM Studio, OpenAI, Gemini) configured via `GUARDRAIL_AI_PROVIDER`, `GUARDRAIL_AI_MODEL`, `OPENAI_API_BASE`, etc. |
| **CLI Gating Flags** | Add `--ai`/`--no-ai` to toggle validation, and `--ai-gating <mode>` (`selective`, `high-only`, `all`) to control AI validation scope. |
| **Prompt Template** | Context snippet → JSON request for `{confirmed, severity, explanation, suggested_fix_diff, false_positive}`. |
| **Cache** | SHA-256 keyed cache (`.guardrail/cache/`) to avoid re-calling the AI engine on unchanged code. |
| **Merge** | Enrich `Finding` with `explanation`, `aiConfirmed`, etc.; drop `false_positive` findings from output. |
| **Graceful Degradation** | If no API keys (`ANTHROPIC_API_KEY` or `OPENAI_API_KEY`) are present, print a helpful info message and run static-only mode. |

**Exit Criteria**
- Injection finding gets `aiConfirmed: true`, `explanation`, and `suggested_fix_diff`.
- Re-scan of unchanged code hits cache → no API call.
- Local/OpenAI-compatible models or Anthropic models can be dynamically configured.


---

## Phase 3 – Pre-Commit & DX (2 days)

- Add `husky` + `lint-staged` to run `guardrail scan` on staged JS/TS files (<5s per diff).
- Implement `guardrail doctor` command to verify dependencies, API key, cache dir, Node version.
- Add colored terminal output via `picocolors`.
- Add `--format github` flag for GitHub Actions annotations.

**Exit Criteria**
- Commit containing a vulnerability in a staged file is blocked.
- `guardrail doctor` reports “All OK” when environment is healthy.
- Terminal colors map severity → red (critical), yellow (high), cyan (low).

---

## Phase 4 – Benchmark & Accuracy (1 week)

- Clone OWASP Juice-Shop & WebGoat into `benchmarks/`.
- Run `guardrail scan` on them, generate SARIF, compute precision/recall.
- Write `benchmarks/results.md` with metrics.
- Reference these numbers in README before any accuracy claim.

---

## Critical File List (by Phase)

| Phase | Files to Create / Modify |
|-------|--------------------------|
| 0 | `CLAUDE.md` (replace), root `package.json`, `tsconfig.base.json`, `.gitignore` |
| 1 | `packages/core/src/analyzer.ts`, `packages/core/src/types.ts`, new `packages/core/rules/semgrep/`, `packages/core/src/tree-sitter.ts`, `packages/core/src/suppression.ts` |
| 2 | `packages/core/src/ai.ts`, `packages/core/src/cache.ts` |
| 3 | `packages/cli/src/index.ts` (CLI), `packages/cli/src/doctor.ts`, `husky` config |
| 4 | `benchmarks/`, `README.md` (add accuracy link) |

---

## Open Decisions (Low-Risk, Reversible)

1. **Semgrep Invocation** – Shell out to binary (recommended) vs. WASM embedding. 
2. **Cache Location** – Repo-local `.guardrail/cache/` (v1) vs. user-global (`~/.cache/`). 
3. **Final Naming** – `guardrail` already set in `package.json` bin field; renaming is trivial. 

---

## Ready-to-Execute Steps

1. Apply the **`CLAUDE.md`** rewrite (overwrites stale SaaS content). 
2. Run the **setup tasks** of Phase 0. 
3. Proceed to **Phase 1** implementation, committing after each sub-task. 

When you’re ready to start coding, issue `ExitPlanMode` to signal that the plan is approved and execution may begin.