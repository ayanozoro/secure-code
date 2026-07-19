import { promises as fs } from 'node:fs';
import { extname } from 'node:path';
import type { Finding } from './types.js';

const SUPPORTED_EXTENSIONS = new Set(['.js', '.jsx', '.ts', '.tsx', '.mjs', '.cjs']);

export function isSupportedSourceFile(path: string): boolean {
  return SUPPORTED_EXTENSIONS.has(extname(path).toLowerCase());
}

export async function runCustomTreeSitterRules(filePaths: string[]): Promise<Finding[]> {
  const findings: Finding[] = [];

  for (const filePath of filePaths) {
    if (!isSupportedSourceFile(filePath)) {
      continue;
    }

    const source = await fs.readFile(filePath, 'utf8');
    const lines = source.split(/\r?\n/);

    // A01 — Broken Access Control
    findings.push(...detectIdorWithoutOwnershipCheck(filePath, lines));
    // A03 — Injection (input validation gaps)
    findings.push(...detectInputValidationGaps(filePath, lines));
    // A02 — Cryptographic Failures
    findings.push(...detectWeakCrypto(filePath, lines));
    findings.push(...detectInsecureCookies(filePath, lines));
    // A10 — SSRF
    findings.push(...detectSsrf(filePath, lines));
    // A05 — Security Misconfiguration
    findings.push(...detectSecurityMisconfiguration(filePath, lines));
  }

  return findings;
}

// ---------------------------------------------------------------------------
// A01 — Broken Access Control: IDOR without ownership check
// ---------------------------------------------------------------------------

function detectIdorWithoutOwnershipCheck(filePath: string, lines: string[]): Finding[] {
  const findings: Finding[] = [];
  const idSourceRegex = /req\.params\.(id|userId|accountId)/;
  const dbUseRegex = /\b(db|repository|model)\b.*\b(find|findOne|query|getById|update|delete)\b/i;
  const ownershipGuardRegex = /(user\.id|ownerId|organizationId|tenantId|isOwner|canAccess)/i;

  for (let index = 0; index < lines.length; index += 1) {
    const currentLine = lines[index] ?? '';
    if (!idSourceRegex.test(currentLine)) {
      continue;
    }

    const windowStart = index;
    const windowEnd = Math.min(lines.length - 1, index + 20);
    const windowLines = lines.slice(windowStart, windowEnd + 1);

    const hasDbUse = windowLines.some((line) => dbUseRegex.test(line));
    const hasOwnershipGuard = windowLines.some((line) => ownershipGuardRegex.test(line));

    if (hasDbUse && !hasOwnershipGuard) {
      findings.push({
        ruleId: 'tree-sitter.missing-ownership-check',
        message: 'Potential IDOR: route parameter is used for data access without an ownership check.',
        severity: 'high',
        engine: 'custom-tree-sitter',
        filePath,
        line: index + 1,
        column: 1,
        fix: 'Validate ownership (user/org/tenant check) before performing DB access.'
      });
    }
  }

  return findings;
}

// ---------------------------------------------------------------------------
// A03 — Injection: unvalidated input into sensitive sink
// ---------------------------------------------------------------------------

function detectInputValidationGaps(filePath: string, lines: string[]): Finding[] {
  const findings: Finding[] = [];
  const inputUseRegex = /req\.(body|query)\.[A-Za-z0-9_]+/;
  const validationRegex = /\b(zod|joi|express-validator|validate|safeParse|schema\.parse)\b/i;
  const sinkRegex = /\b(db\.query|exec|evaluate|render|send|json|insert|update|where)\b/i;

  for (let index = 0; index < lines.length; index += 1) {
    const currentLine = lines[index] ?? '';
    if (!inputUseRegex.test(currentLine)) {
      continue;
    }

    const windowStart = Math.max(0, index - 12);
    const windowEnd = Math.min(lines.length - 1, index + 12);
    const windowLines = lines.slice(windowStart, windowEnd + 1);
    const hasValidation = windowLines.some((line) => validationRegex.test(line));
    const hasSink = windowLines.some((line) => sinkRegex.test(line));

    if (!hasValidation && hasSink) {
      findings.push({
        ruleId: 'tree-sitter.input-validation-gap',
        message: 'Unvalidated request input appears to flow into a sensitive operation.',
        severity: 'medium',
        engine: 'custom-tree-sitter',
        filePath,
        line: index + 1,
        column: 1,
        fix: 'Validate request input with zod/joi/express-validator before use.'
      });
    }
  }

  return findings;
}

// ---------------------------------------------------------------------------
// A02 — Cryptographic Failures: Weak hash / cipher / insecure random
// ---------------------------------------------------------------------------

function detectWeakCrypto(filePath: string, lines: string[]): Finding[] {
  const findings: Finding[] = [];
  const weakHashRegex = /createHash\s*\(\s*["'](md5|sha1|sha-1)["']\s*\)/i;
  const weakCipherRegex = /createCipher(?:iv)?\s*\(\s*["'](des|des-ede|rc2|rc4|blowfish)["']/i;
  const insecureRandomRegex = /Math\.random\s*\(\s*\)/;
  const securityContextRegex = /token|secret|password|salt|nonce|key|csrf|session/i;

  for (let index = 0; index < lines.length; index += 1) {
    const line = lines[index] ?? '';
    const trimmed = line.trimStart();
    if (trimmed.startsWith('//') || trimmed.startsWith('*')) continue;

    if (weakHashRegex.test(line)) {
      const match = weakHashRegex.exec(line);
      const alg = match ? match[1]!.toUpperCase() : 'weak algorithm';
      findings.push({
        ruleId: 'tree-sitter.weak-hash-algorithm',
        message: `Weak cryptographic hash (${alg}) used. ${alg === 'MD5' || alg === 'SHA1' ? 'Broken — collision attacks exist.' : ''} Prefer SHA-256 or stronger.`,
        severity: 'high',
        engine: 'custom-tree-sitter',
        filePath,
        line: index + 1,
        column: 1,
        fix: "Replace with crypto.createHash('sha256'). For passwords, use bcrypt or argon2 instead."
      });
    } else if (weakCipherRegex.test(line)) {
      const match = weakCipherRegex.exec(line);
      const alg = match ? match[1]!.toUpperCase() : 'weak cipher';
      findings.push({
        ruleId: 'tree-sitter.weak-cipher',
        message: `Weak cipher (${alg}) detected. Broken by modern cryptanalysis.`,
        severity: 'high',
        engine: 'custom-tree-sitter',
        filePath,
        line: index + 1,
        column: 1,
        fix: "Use crypto.createCipheriv('aes-256-gcm', key, iv) with a randomly generated key."
      });
    } else if (insecureRandomRegex.test(line)) {
      const windowStart = Math.max(0, index - 8);
      const windowEnd = Math.min(lines.length - 1, index + 4);
      const window = lines.slice(windowStart, windowEnd + 1).join('\n');
      if (securityContextRegex.test(window)) {
        findings.push({
          ruleId: 'tree-sitter.insecure-random',
          message: 'Math.random() is not cryptographically secure and should not be used for tokens, keys, or salts.', // scanner-ignore: rule message string
          severity: 'high',
          engine: 'custom-tree-sitter',
          filePath,
          line: index + 1,
          column: 1,
          fix: 'Use crypto.randomBytes(32) or crypto.getRandomValues() for all security-sensitive randomness.'
        });
      }
    }
  }

  return findings;
}

// ---------------------------------------------------------------------------
// A02 — Cryptographic Failures: Insecure cookie flags
// ---------------------------------------------------------------------------

function detectInsecureCookies(filePath: string, lines: string[]): Finding[] {
  const findings: Finding[] = [];
  const cookieSetRegex = /res\.cookie\s*\(/;

  for (let index = 0; index < lines.length; index += 1) {
    const line = lines[index] ?? '';
    if (!cookieSetRegex.test(line)) continue;

    // Gather the full cookie call (may span up to 5 lines)
    const blockEnd = Math.min(lines.length - 1, index + 5);
    const block = lines.slice(index, blockEnd + 1).join('\n');

    const hasHttpOnly = /httpOnly\s*:\s*true/i.test(block);
    const hasSecure = /secure\s*:\s*true/i.test(block);

    if (!hasHttpOnly || !hasSecure) {
      const missing: string[] = [];
      if (!hasHttpOnly) missing.push('httpOnly: true');
      if (!hasSecure) missing.push('secure: true');
      findings.push({
        ruleId: 'tree-sitter.insecure-cookie',
        message: `Cookie set without ${missing.join(' and ')}. Exposed to XSS or network interception.`,
        severity: 'medium',
        engine: 'custom-tree-sitter',
        filePath,
        line: index + 1,
        column: 1,
        fix: `Add { ${missing.join(', ')}, sameSite: 'strict' } to the cookie options.`
      });
    }
  }

  return findings;
}

// ---------------------------------------------------------------------------
// A10 — SSRF: user-controlled URL passed to HTTP client
// ---------------------------------------------------------------------------

function detectSsrf(filePath: string, lines: string[]): Finding[] {
  const findings: Finding[] = [];
  const httpClientRegex = /\b(?:fetch|axios(?:\.\w+)?|got|http\.get|https\.get|request)\s*\(/;
  const userInputRegex = /req\.(body|query|params)\.[A-Za-z0-9_]+/;
  const urlValidationRegex = /allowlist|whitelist|isValid(?:Url)?|new URL\s*\(|url\.parse|startsWith\s*\(["']https?/i;

  for (let index = 0; index < lines.length; index += 1) {
    const line = lines[index] ?? '';
    if (!httpClientRegex.test(line)) continue;

    const windowStart = Math.max(0, index - 6);
    const windowEnd = Math.min(lines.length - 1, index + 2);
    const block = lines.slice(windowStart, windowEnd + 1).join('\n');

    if (userInputRegex.test(block) && !urlValidationRegex.test(block)) {
      findings.push({
        ruleId: 'tree-sitter.ssrf-user-controlled-url',
        message: 'HTTP request with user-controlled URL and no allowlist validation — potential SSRF.',
        severity: 'high',
        engine: 'custom-tree-sitter',
        filePath,
        line: index + 1,
        column: 1,
        fix: 'Validate the URL against an explicit allowlist of permitted hosts/schemes before making the request.'
      });
    }
  }

  return findings;
}

// ---------------------------------------------------------------------------
// A05 — Security Misconfiguration
// ---------------------------------------------------------------------------

function detectSecurityMisconfiguration(filePath: string, lines: string[]): Finding[] {
  const findings: Finding[] = [];
  const fullSource = lines.join('\n');

  // Check once per file: Express app without Helmet
  const isExpressApp = /require\s*\(['"]express['"]\)|from\s+['"]express['"]/i.test(fullSource);
  const hasHelmet = /require\s*\(['"]helmet['"]\)|from\s+['"]helmet['"]|\.use\s*\(\s*helmet/i.test(fullSource);
  if (isExpressApp && !hasHelmet) {
    findings.push({
      ruleId: 'tree-sitter.missing-helmet',
      message: 'Express app found without Helmet.js — security headers (CSP, HSTS, etc.) are not set.',
      severity: 'medium',
      engine: 'custom-tree-sitter',
      filePath,
      line: 1,
      column: 1,
      fix: "npm install helmet  →  app.use(require('helmet')()) to add secure HTTP response headers."
    });
  }

  // Per-line checks
  for (let index = 0; index < lines.length; index += 1) {
    const line = lines[index] ?? '';
    const trimmed = line.trimStart();
    if (trimmed.startsWith('//') || trimmed.startsWith('*')) continue;

    // Bare cors() — no origin restriction
    if (/\.use\s*\(\s*cors\s*\(\s*\)\s*\)/.test(line)) {
      findings.push({
        ruleId: 'tree-sitter.permissive-cors',
        message: 'CORS enabled with no origin restriction — allows requests from any domain.',
        severity: 'medium',
        engine: 'custom-tree-sitter',
        filePath,
        line: index + 1,
        column: 1,
        fix: "Use cors({ origin: ['https://yourapp.com'] }) to explicitly restrict allowed origins."
      });
    }

    // debug: true in production files
    if (/\bdebug\s*[=:]\s*true\b/.test(line) && /production|prod/i.test(filePath)) {
      findings.push({
        ruleId: 'tree-sitter.debug-in-production',
        message: 'debug: true detected in a production-path file. Verbose errors may leak stack traces.',
        severity: 'medium',
        engine: 'custom-tree-sitter',
        filePath,
        line: index + 1,
        column: 1,
        fix: 'Disable debug mode in production. Use NODE_ENV checks or environment-specific config files.'
      });
    }
  }

  return findings;
}
