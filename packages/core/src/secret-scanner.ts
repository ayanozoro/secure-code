import { promises as fs } from 'node:fs';
import { extname } from 'node:path';
import type { Finding } from './types.js';

const SCANNABLE_EXTENSIONS = new Set([
  '.js', '.jsx', '.ts', '.tsx', '.mjs', '.cjs',
  '.json', '.yaml', '.yml', '.env', '.sh', '.toml', '.config'
]);

export function isScannableFile(filePath: string): boolean {
  const lower = filePath.toLowerCase();
  // Always scan .env files (including .env.local, .env.production, etc.)
  if (lower.endsWith('.env') || /[/\\]\.env\./.test(lower)) return true;
  return SCANNABLE_EXTENSIONS.has(extname(filePath).toLowerCase());
}

interface SecretPattern {
  ruleId: string;
  description: string;
  pattern: RegExp;
  severity: 'critical' | 'high';
}

const SECRET_PATTERNS: SecretPattern[] = [
  {
    ruleId: 'secret.aws-access-key',
    description: 'Hardcoded AWS Access Key ID detected (AKIA…). Rotate immediately.',
    pattern: /\bAKIA[0-9A-Z]{16}\b/,
    severity: 'critical'
  },
  {
    ruleId: 'secret.aws-secret-key',
    description: 'Hardcoded AWS Secret Access Key detected. Rotate immediately.',
    pattern: /(?:aws[_-]?secret[_-]?(?:access[_-]?)?key|aws[_-]?secret)\s*[=:]\s*["']?[A-Za-z0-9/+=]{40}["']?/i,
    severity: 'critical'
  },
  {
    ruleId: 'secret.github-pat',
    description: 'Hardcoded GitHub Personal Access Token (ghp_/gho_/ghs_…) detected.',
    pattern: /\b(ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,}\b/,
    severity: 'critical'
  },
  {
    ruleId: 'secret.stripe-secret-key',
    description: 'Hardcoded Stripe live secret key (sk_live_…) detected.',
    pattern: /\bsk_live_[0-9a-zA-Z]{24,}\b/,
    severity: 'critical'
  },
  {
    ruleId: 'secret.slack-token',
    description: 'Hardcoded Slack token (xoxb-/xoxa-…) detected.',
    pattern: /\bxox[baprs]-[0-9]{10,13}-[0-9]{10,13}(-[a-zA-Z0-9]+)?\b/,
    severity: 'critical'
  },
  {
    ruleId: 'secret.private-key-pem',
    description: 'Private key PEM block found in source file. Never commit private keys.',
    pattern: /-----BEGIN\s+(RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----/,
    severity: 'critical'
  },
  {
    ruleId: 'secret.database-dsn',
    description: 'Database connection string with embedded credentials detected.',
    // Password segment: allow letters, digits, symbols — but not whitespace or quote chars
    pattern: /(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis):\/\/[^:\s"'@]{1,}:[^@\s"']{4,}@/i,
    severity: 'critical'
  },
  {
    ruleId: 'secret.hardcoded-bearer-token',
    description: 'Hardcoded Bearer token in Authorization header value detected.',
    pattern: /Authorization\s*[=:]\s*["']Bearer\s+[A-Za-z0-9\-._~+/]{20,}["']/i,
    severity: 'critical'
  },
  {
    ruleId: 'secret.generic-api-key',
    description: 'Hardcoded API key or access token in assignment detected.',
    pattern: /(?:api[_-]?key|api[_-]?secret|access[_-]?token|auth[_-]?token)\s*[=:]\s*["'][A-Za-z0-9_\-.]{16,}["']/i,
    severity: 'high'
  },
  {
    ruleId: 'secret.hardcoded-password',
    description: 'Hardcoded password value in source code detected.',
    pattern: /(?:^|[^a-z])(?:password|passwd|pwd)\s*[=:]\s*["'][^"'\s]{6,}["']/i,
    severity: 'high'
  },
  {
    ruleId: 'secret.hardcoded-jwt-secret',
    description: 'Hardcoded JWT signing secret detected. Use a strong random secret from env.',
    pattern: /(?:jwt[_-]?secret|signing[_-]?key|token[_-]?secret)\s*[=:]\s*["'][^"'\s]{8,}["']/i,
    severity: 'high'
  },
  {
    ruleId: 'secret.google-api-key',
    description: 'Hardcoded Google API key (AIza…) detected.',
    pattern: /\bAIza[0-9A-Za-z\-_]{35}\b/,
    severity: 'critical'
  },
  {
    ruleId: 'secret.sendgrid-api-key',
    description: 'Hardcoded SendGrid API key (SG.…) detected.',
    pattern: /\bSG\.[A-Za-z0-9_-]{22,}\.[A-Za-z0-9_-]{43,}\b/,
    severity: 'critical'
  },
  {
    ruleId: 'secret.twilio-api-key',
    description: 'Hardcoded Twilio API key (SK…) detected.',
    pattern: /\bSK[a-f0-9]{32}\b/,
    severity: 'high'
  }
];

// Lines that reference obvious placeholder values — skip to reduce false positives.
// Note: we intentionally do NOT include the bare word "example" because
// real AWS key IDs contain "EXAMPLE" (AKIAIOSFODNN7EXAMPLE) in documentation.
const PLACEHOLDER_PHRASES = [
  'placeholder',
  'your-api-key',
  'your_api_key',
  'your-secret',
  'your_secret',
  'your-token',
  'your_token',
  'your-password',
  'your_password',
  'insert-here',
  'insert_here',
  'change-me',
  'changeme',
  'change_me',
  'xxxxxxxxxxxx',
  'dummy-key',
  'dummy_key',
  'test-key',
  'test_key',
  'test-secret',
  'test_secret',
  '<api_key>',
  '<your_key>',
  '<secret>',
];

function isProbablyPlaceholder(line: string): boolean {
  const lower = line.toLowerCase();
  return PLACEHOLDER_PHRASES.some((phrase) => lower.includes(phrase));
}

export async function runSecretScanner(filePaths: string[]): Promise<Finding[]> {
  const findings: Finding[] = [];

  for (const filePath of filePaths) {
    if (!isScannableFile(filePath)) continue;

    let source: string;
    try {
      source = await fs.readFile(filePath, 'utf8');
    } catch {
      continue;
    }

    const lines = source.split(/\r?\n/);

    for (let lineIdx = 0; lineIdx < lines.length; lineIdx++) {
      const line = lines[lineIdx] ?? '';

      // Skip pure comment lines (basic heuristic)
      const trimmed = line.trimStart();
      if (trimmed.startsWith('//') || trimmed.startsWith('#') || trimmed.startsWith('*')) {
        continue;
      }

      if (isProbablyPlaceholder(line)) continue;

      for (const sp of SECRET_PATTERNS) {
        if (sp.pattern.test(line)) {
          findings.push({
            ruleId: sp.ruleId,
            message: sp.description,
            severity: sp.severity,
            engine: 'secret-scanner',
            filePath,
            line: lineIdx + 1,
            column: 1,
            fix: 'Remove the hardcoded secret. Store it in an environment variable or a secrets manager (e.g. Vault, AWS Secrets Manager).'
          });
          // One finding per line maximum
          break;
        }
      }
    }
  }

  return findings;
}
