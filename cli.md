# CLI Development Guide — AI-Powered Secure Code Checker

> Distilled from `securecode.md` (master spec). This file focuses on **Phase 1: the CLI / pre-commit tool** only.
> CI/CD (Phase 2) and VSCode extension (Phase 3) are out of scope for now but the repo structure must allow them to import the same core engine.

---

## 1. What We're Building (CLI Focus)

A **hybrid static + AI code security checker** that runs locally as a CLI and a pre-commit hook.

**What it catches (Phase 1 scope only):**
- Injection (A03)
- Broken Access Control (A01)
- Input validation gaps

**What it does NOT do (Phase 1):**
- Crypto failures, misconfig, SSRF/deserialization, hardcoded secrets — those categories come later
- General bug/logic-error detection (different problem)
- Deep secret scanning (that's the separate `leak-radar` project)
- Non-JS/TS languages (v1 is JavaScript/TypeScript only)

**Positioning:** "The security review of a senior AppSec engineer, running locally, before code ever leaves your machine."

**MVP deliverable line:** `npx <tool-name> scan .` runs locally, flags Injection / Access-Control / Validation issues with AI-confirmed severity and suggested fixes, exits non-zero on high/critical.

---

## 2. Tech Stack (CLI-relevant)

| Concern | Choice |
|---|---|
| Language | TypeScript on Node.js |
| CLI framework | `commander` **or** `yargs` (pick one) |
| Static analysis engine | **Semgrep** (wrapped, NOT reimplemented) + custom tree-sitter queries for gaps |
| AST parsing | `tree-sitter` (`web-tree-sitter` or `node-tree-sitter`) / `ts-morph` for JS/TS |
| AI layer | Claude API (`claude-sonnet-4-6` or latest), structured JSON output, low temperature |
| Output format | **SARIF** (Static Analysis Results Interchange Format) — consumable by GitHub/VSCode natively |
| Terminal output | colored |
| Pre-commit hook | `husky` + `lint-staged` |
| Benchmark corpus | OWASP Juice Shop / WebGoat (known-vulnerable) |

**Packaging principle:** Core engine is a standalone npm package. CLI, (future) GitHub Action, and (future) VSCode extension all import it. Do NOT couple analysis logic into the CLI binary.

---

## 3. Architecture (Core Engine)

```
┌─────────────────────────────────────────┐
│           Core Analysis Engine            │
│  (published npm package — the real product)│
│                                             │
│  1. Parser layer (tree-sitter / ts-morph)  │
│  2. Static rule engine (Semgrep + custom)  │
│  3. AI review layer (Claude API)           │
│  4. Finding aggregator + dedup + SARIF out │
└─────────────────────────────────────────┘
        ↓
   CLI / pre-commit   (Phase 1 - MVP)
```

### 3.1 Parser layer
- Use `tree-sitter` for JS/TS ASTs.
- Goal: **structural** rules ("this variable flows from `req.body` into a SQL query without sanitization"), NOT text/regex matching.

### 3.2 Static rule engine (runs FIRST — cheap, deterministic, zero API cost)
- Wrap **Semgrep** as primary engine. Don't reimplement taint tracking.
- Supplement with custom rules for gaps Semgrep misses.

**Phase 1 rule categories:**

| Category | OWASP | Pattern examples |
|---|---|---|
| Injection | A03 | String concat/template literals into `db.query()`, `exec()`, `eval()`, raw SQL builders |
| Broken Access Control | A01 | Missing auth middleware on route handlers; IDOR (`req.params.id` used directly in DB lookup with no ownership check) |
| Input validation gaps | — | `req.body`/`req.query` fields used without passing through Zod/Joi/express-validator first |

> Categories deferred to later phases (do NOT build now): Crypto failures (A02), Security misconfig (A05), SSRF/deserialization, Hardcoded secrets (baseline).

### 3.3 AI layer (contextual validation — NOT blind LLM-over-everything)
Only send to Claude:
- Files/diffs **already flagged by the static layer** (confirm true positive vs. false positive, explain exploitability)
- Files touching **auth, payments, file uploads, or DB access** even if static rules didn't fire (semantic cases static rules miss)

**Per-finding prompt returns structured JSON:**
```json
{
  "confirmed": true,
  "severity": "high",
  "explanation": "...",
  "suggested_fix_diff": "...",
  "false_positive": false
}
```

- Low temperature, deterministic system prompt.
- **Cache by code-snippet hash** so re-scans of unchanged code don't re-call the API or produce inconsistent verdicts.
- This cuts API cost ~80–90% vs. scanning every file with AI.

### 3.4 Output layer
- **CLI:** colored terminal output; **non-zero exit code on high/critical** findings (for pre-commit gating).
- **SARIF file output** for CI/VSCode consumption.
- **Suppression from day one:** `// scanner-ignore: reason` inline comment support. False-positive fatigue is the #1 adoption killer for this category of tool.

---

## 4. Phase 1 Build Plan (CLI MVP — 2–3 weeks)

### Week 1
- [ ] Scaffold npm package structure for core engine
- [ ] Wrap Semgrep, run its default OWASP rule pack, parse output
- [ ] Add custom tree-sitter rules for the 1–2 gaps Semgrep doesn't cover well in target patterns
- [ ] Build CLI wrapper (`commander`), `scan <path>` command, colored terminal output

### Week 2
- [ ] Wire Claude API layer: send static findings + surrounding function context, get back structured JSON
- [ ] Implement suppression comments (`// scanner-ignore: reason`)
- [ ] SARIF output writer
- [ ] Pre-commit hook integration (husky/lint-staged)
- [ ] Benchmark against Juice Shop / WebGoat: measure true positive / false positive rate, write it down

### Deliverable
`npx <tool-name> scan .` runs locally, flags Injection/Access-Control/Validation issues with AI-confirmed severity and suggested fixes, exits non-zero on high/critical.

---

## 5. Non-Negotiable Design Principles

1. **False positives are the #1 risk.** Tune aggressively; ship suppression from day one; benchmark against known-vulnerable test repos before claiming any accuracy numbers.
2. **Static first, AI second.** Never send every file to the LLM — only static-flagged files and high-risk paths (auth/payment/upload/DB).
3. **Deterministic where it matters.** Static rules must be 100% reproducible. AI layer should minimize non-determinism via low temperature + hash-based caching.
4. **Narrow scope, honest claims.** Don't market as general "bug detection" — that's a different (fuzzier) problem. Stay in the security lane.
5. **Lean on existing tools.** Use Semgrep rather than rebuilding taint-tracking from scratch. The differentiation is the AI layer + DX, not reinventing SAST.

---

## 6. Success Criteria for MVP (Phase 1)

- [ ] Correctly flags known vulnerabilities in a sample of Juice Shop / WebGoat routes (document the true/false positive rate)
- [ ] Runs as a pre-commit hook without noticeably slowing down commits (**<5s for a typical diff**)
- [ ] Produces valid SARIF output
- [ ] Has a suppression mechanism that works
- [ ] README with architecture diagram + a recorded demo (find → explain → suggest fix)

---

## 7. Build Prompt (paste into Claude Code when starting)

> Build a TypeScript CLI tool called `[NAME]` that performs hybrid static + AI security analysis on JavaScript/TypeScript codebases. Core engine as a standalone npm package with: (1) a Semgrep wrapper running OWASP rule packs, (2) custom tree-sitter queries for injection, broken access control, and input validation gaps not covered by Semgrep defaults, (3) an AI review layer using the Claude API that receives only Semgrep/tree-sitter-flagged code plus surrounding function context, and returns structured JSON with confirmed/severity/explanation/suggested_fix_diff/false_positive fields, (4) a SARIF output writer, (5) inline suppression comment support (`// scanner-ignore: reason`). CLI command `scan <path>` with colored terminal output and non-zero exit code on high/critical findings. Start with Injection, Broken Access Control, and Input Validation gaps only — do not implement other OWASP categories yet. Use low temperature and hash-based caching for the AI layer to keep results deterministic. Structure the repo so a pre-commit hook, GitHub Action, and future VSCode extension can all import the same core engine package.

> Pick a `[NAME]` before starting — candidates from spec: `guardrail`, `codesentry`, `sentrycheck`.

---

## 8. CLI Command Surface (derived from spec)

```bash
# Core
<name> scan <path>          # Run static + AI analysis, colored output, exit non-zero on high/critical
<name> scan <path> --format=sarif -o report.sarif   # SARIF file output

# Suppression
# (handled via inline comments in source: // scanner-ignore: reason)

# Pre-commit (via husky + lint-staged)
# runs `scan` on staged files only
```

Exit codes:
- `0` — no high/critical findings (or only suppressed/low/medium)
- `non-zero` — high/critical findings present (gates the commit)

---

## 9. Quick Reference — Phase 1 Boundaries

| Do now | Defer |
|---|---|
| Injection (A03) | Crypto failures (A02) |
| Broken Access Control (A01) | Security misconfig (A05) |
| Input validation gaps | SSRF / deserialization |
| Semgrep wrapper + tree-sitter gaps | Hardcoded secrets (baseline net) |
| Claude AI confirm/exploit/fix layer | Other JS/TS以外的 languages |
| Colored CLI + SARIF + suppression | VSCode extension / GitHub Action |
| Pre-commit hook (husky/lint-staged) | PR comment bot, incremental caching |
| Juice Shop/WebGoat benchmark | Deep secret scanning (leak-radar) |
