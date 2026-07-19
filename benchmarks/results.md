# Guardrail Security Scanner Benchmark Results

*Generated on: 2026-07-19T12:38:01.256Z*

This report outlines the baseline scan metrics for the `guardrail` scanner against two popular vulnerable target codebases.

## Benchmark Overview

| Target | Language / Type | Scan Duration | Total Findings | High/Critical | Medium (Warning) | Low (Note) |
| ------ | --------------- | ------------- | -------------- | ------------- | ---------------- | ---------- |
| OWASP Juice-Shop | JS/TS Vulnerable App | 1.95s | 419 | 172 | 247 | 0 |
| OWASP NodeGoat | JS/TS Vulnerable App | 1.41s | 11 | 6 | 5 | 0 |

## Details & Severity Analysis

### OWASP Juice-Shop

**Vulnerability Findings Count by Rule ID:**

| Rule ID | Count |
| ------- | ----- |
| sca.vulnerable-dependency | 2 |
| secret.hardcoded-bearer-token | 4 |
| secret.hardcoded-password | 157 |
| secret.private-key-pem | 1 |
| tree-sitter.input-validation-gap | 125 |
| tree-sitter.insecure-cookie | 2 |
| tree-sitter.insecure-random | 3 |
| tree-sitter.missing-helmet | 119 |
| tree-sitter.missing-ownership-check | 2 |
| tree-sitter.permissive-cors | 1 |
| tree-sitter.ssrf-user-controlled-url | 1 |
| tree-sitter.weak-hash-algorithm | 2 |

### OWASP NodeGoat

**Vulnerability Findings Count by Rule ID:**

| Rule ID | Count |
| ------- | ----- |
| sca.vulnerable-dependency | 1 |
| secret.generic-api-key | 2 |
| tree-sitter.input-validation-gap | 3 |
| tree-sitter.insecure-cookie | 1 |
| tree-sitter.insecure-random | 3 |
| tree-sitter.missing-helmet | 1 |

