import { resolve } from 'node:path';
import type { Finding, ScanRequest, ScanResult } from './types.js';

export async function scan(request: ScanRequest): Promise<ScanResult> {
  const targetPath = resolve(request.targetPath);
  const findings = await scanPath(targetPath);
  const hasBlockingFinding = findings.some((finding) => finding.severity === 'high' || finding.severity === 'critical');

  return {
    findings,
    exitCode: hasBlockingFinding ? 1 : 0
  };
}

async function scanPath(_targetPath: string): Promise<Finding[]> {
  // Placeholder until Semgrep/tree-sitter/Claude wiring lands.
  return [];
}
