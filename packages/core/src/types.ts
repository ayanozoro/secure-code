export type Severity = 'low' | 'medium' | 'high' | 'critical';

export interface Finding {
  ruleId: string;
  message: string;
  severity: Severity;
  filePath: string;
  line: number;
  column?: number;
  fix?: string;
  suppressed?: boolean;
}

export interface ScanRequest {
  targetPath: string;
  format?: 'terminal' | 'sarif';
}

export interface ScanResult {
  findings: Finding[];
  exitCode: number;
}
