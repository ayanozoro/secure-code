export type Severity = 'low' | 'medium' | 'high' | 'critical';
export type FindingEngine = 'semgrep' | 'custom-tree-sitter';

export interface Finding {
  ruleId: string;
  message: string;
  severity: Severity;
  engine: FindingEngine;
  filePath: string;
  line: number;
  column?: number;
  fix?: string;
  suppressed?: boolean;
  suppressionReason?: string;
}

export interface ScanRequest {
  targetPath: string;
  format?: 'terminal' | 'sarif';
}

export interface ScanResult {
  findings: Finding[];
  sarifFindings: Finding[];
  warnings: string[];
  exitCode: number;
}
