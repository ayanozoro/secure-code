import { promises as fs } from 'node:fs';
import { join, resolve } from 'node:path';
import { runSemgrep } from './semgrep.js';
import { applySuppressions } from './suppression.js';
import { isSupportedSourceFile, runCustomTreeSitterRules } from './tree-sitter.js';
import type { Finding, ScanRequest, ScanResult } from './types.js';

export async function scan(request: ScanRequest): Promise<ScanResult> {
  const targetPath = resolve(request.targetPath);
  const { findings, warnings } = await scanPath(targetPath);
  const sourceMap = await readSourceByFilePath(findings);
  const findingsWithSuppressions = applySuppressions(findings, sourceMap);
  const visibleFindings = findingsWithSuppressions.filter((finding) => !finding.suppressed);
  const sarifFindings = findingsWithSuppressions;
  const hasBlockingFinding = visibleFindings.some((finding) => finding.severity === 'high' || finding.severity === 'critical');

  return {
    findings: visibleFindings,
    sarifFindings,
    warnings,
    exitCode: hasBlockingFinding ? 1 : 0
  };
}

async function scanPath(targetPath: string): Promise<{ findings: Finding[]; warnings: string[] }> {
  const sourceFiles = await collectSourceFiles(targetPath);
  const semgrepResult = await runSemgrep(targetPath);
  const treeSitterFindings = await runCustomTreeSitterRules(sourceFiles);
  const deduped = dedupeFindings([...semgrepResult.findings, ...treeSitterFindings]);

  return {
    findings: deduped,
    warnings: semgrepResult.warnings
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
