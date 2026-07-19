import { promises as fs } from 'node:fs';
import { join, resolve, extname } from 'node:path';
import { runSemgrep } from './semgrep.js';
import { applySuppressions } from './suppression.js';
import { isSupportedSourceFile, runCustomTreeSitterRules } from './tree-sitter.js';
import type { Finding, ScanRequest, ScanResult } from './types.js';
import { getAiConfig, validateFinding } from './ai.js';
import { computeCacheKey, getCachedValidation, setCachedValidation } from './cache.js';
import { runSecretScanner, isScannableFile } from './secret-scanner.js';
import { runScaScan } from './sca-scanner.js';

export async function scan(request: ScanRequest): Promise<ScanResult> {
  const targetPath = resolve(request.targetPath);
  const { findings, warnings: scanWarnings } = await scanPath(targetPath);
  const sourceMap = await readSourceByFilePath(findings);
  const findingsWithSuppressions = applySuppressions(findings, sourceMap);
  const visibleFindings = findingsWithSuppressions.filter((finding) => !finding.suppressed);
  const warnings = [...scanWarnings];

  let finalFindings = visibleFindings;
  const isAiDisabled = request.ai === false;

  if (!isAiDisabled) {
    const aiConfig = getAiConfig(targetPath);
    if (!aiConfig) {
      if (request.ai === true) {
        warnings.push(
          'AI validation was explicitly requested (--ai), but no credentials were found. Please set ANTHROPIC_API_KEY or OPENAI_API_KEY.'
        );
      } else {
        warnings.push(
          'AI verification is disabled (no API keys found). Running in static-only mode. Set OPENAI_API_KEY or ANTHROPIC_API_KEY to enable.'
        );
      }
    } else {
      const gatingMode = request.aiGating || 'selective';
      const enrichedFindings: Finding[] = [];

      for (const finding of visibleFindings) {
        if (shouldValidateWithAi(finding, gatingMode)) {
          const source = sourceMap.get(finding.filePath) || '';
          const snippet = getSnippet(source, finding.line);
          const cacheKey = computeCacheKey(finding.ruleId, finding.filePath, snippet);

          let validation = await getCachedValidation(targetPath, cacheKey);
          if (!validation) {
            try {
              validation = await validateFinding(finding, snippet, aiConfig);
              await setCachedValidation(targetPath, cacheKey, validation);
            } catch (err) {
              warnings.push(`AI validation failed for ${finding.filePath}:${finding.line}: ${(err as Error).message}`);
            }
          }

          if (validation) {
            if (validation.falsePositive) {
              // Exclude from final output
              continue;
            }
            finding.aiConfirmed = validation.confirmed;
            finding.severity = validation.severity;
            finding.explanation = validation.explanation;
            finding.suggestedFixDiff = validation.suggestedFixDiff;
          }
        }
        enrichedFindings.push(finding);
      }
      finalFindings = enrichedFindings;
    }
  }

  const sarifFindings = findingsWithSuppressions;
  const hasBlockingFinding = finalFindings.some(
    (finding) => finding.severity === 'high' || finding.severity === 'critical'
  );

  return {
    findings: finalFindings,
    sarifFindings,
    warnings,
    exitCode: hasBlockingFinding ? 1 : 0
  };
}

function shouldValidateWithAi(finding: Finding, gating: 'selective' | 'high-only' | 'all'): boolean {
  // Secret and SCA findings are deterministic — skip AI re-validation
  if (finding.engine === 'secret-scanner' || finding.engine === 'sca') {
    return false;
  }
  if (gating === 'all') {
    return true;
  }
  const isHighOrCritical = finding.severity === 'high' || finding.severity === 'critical';
  if (gating === 'high-only') {
    return isHighOrCritical;
  }

  if (isHighOrCritical) {
    return true;
  }

  const sensitivePatterns = /auth|payment|upload|db|query|admin|login|register|session/i;
  return sensitivePatterns.test(finding.filePath);
}

function getSnippet(source: string, line: number, contextRange = 5): string {
  const lines = source.split(/\r?\n/);
  const startIdx = Math.max(0, line - 1 - contextRange);
  const endIdx = Math.min(lines.length - 1, line - 1 + contextRange);

  return lines
    .slice(startIdx, endIdx + 1)
    .map((l, i) => `${startIdx + i + 1}: ${l}`)
    .join('\n');
}


async function scanPath(targetPath: string): Promise<{ findings: Finding[]; warnings: string[] }> {
  const sourceFiles = await collectSourceFiles(targetPath);
  const textFiles = await collectTextFiles(targetPath);

  const [semgrepResult, treeSitterFindings, secretFindings, scaResult] = await Promise.all([
    runSemgrep(targetPath),
    runCustomTreeSitterRules(sourceFiles),
    runSecretScanner(textFiles),
    runScaScan(targetPath)
  ]);

  const deduped = dedupeFindings([
    ...semgrepResult.findings,
    ...treeSitterFindings,
    ...secretFindings,
    ...scaResult.findings
  ]);

  return {
    findings: deduped,
    warnings: [...semgrepResult.warnings, ...scaResult.warnings]
  };
}

async function collectSourceFiles(targetPath: string): Promise<string[]> {
  const stat = await fs.stat(targetPath);
  if (stat.isFile()) {
    return isSupportedSourceFile(targetPath) ? [targetPath] : [];
  }

  const found: string[] = [];
  const stack = [targetPath];
  while (stack.length > 0) {
    const current = stack.pop();
    if (!current) {
      continue;
    }

    const entries = await fs.readdir(current, { withFileTypes: true });
    for (const entry of entries) {
      if (entry.name === 'node_modules' || entry.name === 'dist' || entry.name.startsWith('.')) {
        continue;
      }

      const fullPath = join(current, entry.name);
      if (entry.isDirectory()) {
        stack.push(fullPath);
      } else if (entry.isFile() && isSupportedSourceFile(fullPath)) {
        found.push(resolve(fullPath));
      }
    }
  }

  return found;
}

/**
 * Collect all text files that the secret scanner can process:
 * JS/TS source files plus config files (.json, .yaml, .yml, .env, .sh, .toml).
 */
async function collectTextFiles(targetPath: string): Promise<string[]> {
  const EXTRA_EXTENSIONS = new Set(['.json', '.yaml', '.yml', '.env', '.sh', '.toml', '.config']);
  const SKIP_DIRS = new Set(['node_modules', 'dist', 'build', 'coverage', '.git']);

  const stat = await fs.stat(targetPath);
  if (stat.isFile()) {
    return [resolve(targetPath)];
  }

  const found: string[] = [];
  const stack = [targetPath];

  while (stack.length > 0) {
    const current = stack.pop();
    if (!current) continue;

    const entries = await fs.readdir(current, { withFileTypes: true });
    for (const entry of entries) {
      if (SKIP_DIRS.has(entry.name) || entry.name.startsWith('.git')) continue;

      const fullPath = join(current, entry.name);
      if (entry.isDirectory()) {
        stack.push(fullPath);
      } else if (entry.isFile()) {
        const ext = extname(entry.name).toLowerCase();
        const lowerName = entry.name.toLowerCase();
        const isEnvFile = lowerName === '.env' || lowerName.startsWith('.env.');
        if (isSupportedSourceFile(fullPath) || EXTRA_EXTENSIONS.has(ext) || isEnvFile) {
          found.push(resolve(fullPath));
        }
      }
    }
  }

  return found;
}

async function readSourceByFilePath(findings: Finding[]): Promise<Map<string, string>> {
  const uniquePaths = [...new Set(findings.map((finding) => finding.filePath))];
  const entries = await Promise.all(
    uniquePaths.map(async (filePath) => {
      try {
        const source = await fs.readFile(filePath, 'utf8');
        return [filePath, source] as const;
      } catch {
        return [filePath, ''] as const;
      }
    })
  );

  return new Map(entries);
}

function dedupeFindings(findings: Finding[]): Finding[] {
  const byKey = new Map<string, Finding>();

  for (const finding of findings) {
    const key = `${finding.ruleId}::${finding.filePath}::${finding.line}`;
    if (!byKey.has(key)) {
      byKey.set(key, finding);
    }
  }

  return [...byKey.values()];
}
