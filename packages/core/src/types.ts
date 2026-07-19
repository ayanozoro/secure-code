export type Severity = 'low' | 'medium' | 'high' | 'critical';
export type FindingEngine = 'semgrep' | 'custom-tree-sitter' | 'secret-scanner' | 'sca';

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
  aiConfirmed?: boolean;
  explanation?: string;
  suggestedFixDiff?: string;
}

export interface ScanRequest {
  targetPath: string;
  format?: 'terminal' | 'sarif';
  ai?: boolean;
  aiGating?: 'selective' | 'high-only' | 'all';
}

export interface AiValidation {
  confirmed: boolean;
  severity: Severity;
  explanation: string;
  suggestedFixDiff: string;
  falsePositive: boolean;
}

export interface ScanResult {
  findings: Finding[];
  sarifFindings: Finding[];
  warnings: string[];
  exitCode: number;
}


