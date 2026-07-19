import type { Finding } from './types.js';

export function findingsToSarif(findings: Finding[]): unknown {
  return {
    version: '2.1.0',
    $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
    runs: [
      {
        tool: {
          driver: {
            name: 'guardrail',
            informationUri: 'https://example.invalid'
          }
        },
        results: findings.map((finding) => ({
          ruleId: finding.ruleId,
          level: mapSeverityToSarifLevel(finding.severity),
          message: {
            text: finding.message
          },
          suppressions: finding.suppressed
            ? [
                {
                  kind: 'inSource',
                  justification: finding.suppressionReason ?? 'Suppressed via scanner-ignore comment.'
                }
              ]
            : undefined,
          locations: [
            {
              physicalLocation: {
                artifactLocation: {
                  uri: finding.filePath
                },
                region: {
                  startLine: finding.line,
                  startColumn: finding.column ?? 1
                }
              }
            }
          ]
        }))
      }
    ]
  };
}

function mapSeverityToSarifLevel(severity: Finding['severity']): 'note' | 'warning' | 'error' {
  if (severity === 'low') {
    return 'note';
  }
  if (severity === 'medium') {
    return 'warning';
  }
  return 'error';
}
