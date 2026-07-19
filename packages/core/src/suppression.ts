import type { Finding } from './types.js';

const SUPPRESSION_TOKEN = 'scanner-ignore:';

export function isSuppressedSourceLine(line: string): boolean {
  return line.includes(SUPPRESSION_TOKEN);
}

export function getSuppressionReason(line: string): string | undefined {
  const markerIndex = line.indexOf(SUPPRESSION_TOKEN);
  if (markerIndex < 0) {
    return undefined;
  }

  const reason = line.slice(markerIndex + SUPPRESSION_TOKEN.length).trim();
  return reason.length > 0 ? reason : undefined;
}

export function applySuppressions(findings: Finding[], fileContentsByPath: Map<string, string>): Finding[] {
  return findings.map((finding) => {
    const source = fileContentsByPath.get(finding.filePath);
    if (!source) {
      return finding;
    }

    const lines = source.split(/\r?\n/);
    const currentLine = lines[Math.max(finding.line - 1, 0)] ?? '';
    const previousLine = lines[Math.max(finding.line - 2, 0)] ?? '';

    if (isSuppressedSourceLine(currentLine)) {
      return {
        ...finding,
        suppressed: true,
        suppressionReason: getSuppressionReason(currentLine)
      };
    }

    if (isSuppressedSourceLine(previousLine)) {
      return {
        ...finding,
        suppressed: true,
        suppressionReason: getSuppressionReason(previousLine)
      };
    }

    return finding;
  });
}
