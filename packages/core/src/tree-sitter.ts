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

    findings.push(...detectIdorWithoutOwnershipCheck(filePath, lines));
    findings.push(...detectInputValidationGaps(filePath, lines));
  }

  return findings;
}

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
