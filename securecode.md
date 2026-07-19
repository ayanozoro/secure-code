# Project Prompt: AI-Powered Secure Code Checker

Use this as the master spec — hand it to Claude Code, paste it into a new repo's `PROJECT.md`, or use it to brief yourself before each build session.

---

## 1. Project Summary

Build a **hybrid static + AI code security checker** for developers, catching:
- OWASP Top 10 vulnerabilities (starting with Injection, Broken Access Control, Input Validation gaps)
- Missing/improper input validation
- Hardcoded secrets (lightweight baseline net — full depth stays in the separate `leak-radar` project)

It runs at three points in the dev lifecycle, built in phases from one shared core engine:
1. **CLI / pre-commit hook** (Phase 1 — MVP)
2. **CI/CD check (GitHub Action)** (Phase 2)
3. **VSCode extension (real-time)** (Phase 3)

**Positioning:** "The security review of a senior AppSec engineer, running locally, before code ever leaves your machine."

**Explicitly out of scope:** general bug/logic-error detection, deep secret-scanning (leak-radar's job), non-JS/TS languages (v1).

---

## 2. Tech Stack

- **Language:** TypeScript (Node.js)
- **Static analysis engine:** Semgrep (wrapped, not reimplemented) + custom tree-sitter queries for gaps Semgrep misses
- **AI layer:** Claude API (`claude-sonnet-4-6` or latest), structured JSON output, low temperature
- **Output format:** SARIF (Static Analysis Results Interchange Format) — standard, consumable by GitHub/VSCode natively
- **CLI framework:** `commander` or `yargs`
- **Testing corpus:** OWASP Juice Shop / WebGoat (known-vulnerable) as accuracy benchmarks
- **Packaging:** Core engine as a standalone npm package; CLI, GitHub Action, and VSCode extension all import it

---

## 3. Architecture

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
        ↓              ↓              ↓
   CLI / pre-commit   CI/CD action   VSCode ext
   (Phase 1 - MVP)    (Phase 2)      (Phase 3)
```

### 3.1 Parser layer
- Use `tree-sitter` (via `web-tree-sitter` or `node-tree-sitter`) for JS/TS ASTs.
- Goal: structural rules ("this variable flows from `req.body` into a SQL query without sanitization"), not text/regex matching.

### 3.2 Static rule engine (runs first — cheap, deterministic, zero API cost)
Wrap **Semgrep** as the primary engine (don't reimplement taint tracking from scratch). Supplement with custom rules for gaps. Cover:

| Category | Pattern examples |
|---|---|
| Injection (A03) | String concat/template literals into `db.query()`, `exec()`, `eval()`, raw SQL builders |
| Broken Access Control (A01) | Missing auth middleware on route handlers; IDOR (`req.params.id` used directly in DB lookup with no ownership check) |
| Input validation gaps | `req.body`/`req.query` fields used without passing through Zod/Joi/express-validator first |
| Cryptographic failures (A02) | `md5`/`sha1` for passwords; hardcoded IVs; `Math.random()` for tokens/session IDs |
| Security misconfiguration (A05) | Missing `helmet`; permissive CORS (`origin: '*'` + credentials); debug flags left on |
| SSRF / insecure deserialization | `fetch(userControlledUrl)`; `eval(JSON)`; dynamic `require()` of unsanitized paths |
| Hardcoded secrets (baseline only) | Obvious `API_KEY = "sk-..."` patterns — not the full leak-radar depth |

**Phase 1 scope: only Injection + Broken Access Control + Input Validation gaps.** Don't try to ship all seven categories at once.

### 3.3 AI layer (contextual validation — not blind LLM-over-everything)
Only send to Claude:
- Files/diffs already flagged by the static layer (confirm true positive vs. false positive, explain exploitability)
- Files touching auth, payments, file uploads, or DB access even if static rules didn't fire (semantic cases static rules miss)

**Per-finding prompt should ask Claude to return structured JSON with:**
```json
{
  "confirmed": true,
  "severity": "high",
  "explanation": "...",
  "suggested_fix_diff": "...",
  "false_positive": false
}
```
- Low temperature, deterministic system prompt, cache by code-snippet hash so re-scans of unchanged code don't re-call the API or produce inconsistent verdicts.
- This should cut API cost ~80-90% vs. scanning every file with AI.

### 3.4 Output layer
- CLI: colored terminal output; non-zero exit code on high/critical findings (for pre-commit gating)
- SARIF file output for CI/VSCode consumption
- Suppression mechanism from day one: `// scanner-ignore: reason` inline comment support — false-positive fatigue is the #1 adoption killer for this category of tool

---

## 4. Phased Build Plan

### Phase 1 — CLI MVP (2-3 weeks)
**Week 1:**
- [ ] Scaffold npm package structure for core engine
- [ ] Wrap Semgrep, run its default OWASP rule pack, parse output
- [ ] Add custom tree-sitter rules for the 1-2 gaps Semgrep doesn't cover well in your target patterns
- [ ] Build CLI wrapper (`commander`), `scan <path>` command, colored terminal output

**Week 2:**
- [ ] Wire Claude API layer: send static findings + surrounding function context, get back structured JSON
- [ ] Implement suppression comments (`// scanner-ignore: reason`)
- [ ] SARIF output writer
- [ ] Pre-commit hook integration (husky/lint-staged)
- [ ] Benchmark against Juice Shop / WebGoat: measure true positive / false positive rate, write it down

**Deliverable:** `npx <tool-name> scan .` runs locally, flags Injection/Access-Control/Validation issues with AI-confirmed severity and suggested fixes, exits non-zero on high/critical.

### Phase 2 — CI/CD (after Phase 1 is stable)
- [ ] GitHub Action wrapping the CLI
- [ ] PR comment bot posting findings inline via GitHub API
- [ ] Cache layer so unchanged files aren't re-scanned by AI on every CI run

### Phase 3 — VSCode Extension (after Phase 2)
- [ ] LSP-style diagnostics, squiggly underlines
- [ ] Hover explanations pulled from AI layer
- [ ] Code actions for AI-suggested fixes
- [ ] Debouncing + incremental analysis (only re-scan changed functions) — full static+AI scan on every keystroke is not feasible

---

## 5. Non-Negotiable Design Principles

1. **False positives are the #1 risk.** Tune aggressively; ship suppression from day one; benchmark against known-vulnerable test repos before claiming any accuracy numbers.
2. **Static first, AI second.** Never send every file to the LLM — only static-flagged files and high-risk paths (auth/payment/upload/DB).
3. **Deterministic where it matters.** Static rules must be 100% reproducible. AI layer should minimize non-determinism via low temperature + hash-based caching.
4. **Narrow scope, honest claims.** Don't market this as general "bug detection" — that's a different (fuzzier) problem. Stay in the security lane.
5. **Lean on existing tools.** Use Semgrep for static analysis rather than rebuilding taint-tracking from scratch — the differentiation is the AI layer + DX, not reinventing SAST.

---

## 6. Success Criteria for MVP (Phase 1)

- [ ] Correctly flags known vulnerabilities in a sample of Juice Shop / WebGoat routes (document the true/false positive rate)
- [ ] Runs as a pre-commit hook without noticeably slowing down commits (<5s for a typical diff)
- [ ] Produces valid SARIF output
- [ ] Has a suppression mechanism that works
- [ ] README with architecture diagram + a recorded demo (find → explain → suggest fix)

---

## 7. Prompt to Use with Claude Code / an AI Coding Assistant

Copy this in directly when you start building:

> Build a TypeScript CLI tool called `[NAME]` that performs hybrid static + AI security analysis on JavaScript/TypeScript codebases. Core engine as a standalone npm package with: (1) a Semgrep wrapper running OWASP rule packs, (2) custom tree-sitter queries for injection, broken access control, and input validation gaps not covered by Semgrep defaults, (3) an AI review layer using the Claude API that receives only Semgrep/tree-sitter-flagged code plus surrounding function context, and returns structured JSON with confirmed/severity/explanation/suggested_fix_diff/false_positive fields, (4) a SARIF output writer, (5) inline suppression comment support (`// scanner-ignore: reason`). CLI command `scan <path>` with colored terminal output and non-zero exit code on high/critical findings. Start with Injection, Broken Access Control, and Input Validation gaps only — do not implement other OWASP categories yet. Use low temperature and hash-based caching for the AI layer to keep results deterministic. Structure the repo so a pre-commit hook, GitHub Action, and future VSCode extension can all import the same core engine package.

---

*Fill in `[NAME]` once you've picked one (e.g. `guardrail`, `codesentry`, `sentrycheck`).*