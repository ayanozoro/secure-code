#!/usr/bin/env node
import { Command } from 'commander';
import { writeFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import pc from 'picocolors';
import { findingsToSarif, scan, getAiConfig, type Finding } from '@securecode/core';
import { runDoctor } from './doctor.js';

const program = new Command();

program
  .name('guardrail')
  .description('Local hybrid static + AI security scanner for JS/TS codebases')
  .version('0.1.0');

program
  .command('doctor')
  .description('Verify local configuration, dependencies, and environment health')
  .action(async () => {
    const exitCode = await runDoctor();
    process.exit(exitCode);
  });

program
  .command('scan')
  .argument('<paths...>', 'paths to files or directories')
  .option('-f, --format <format>', 'output format (terminal, sarif, github)', 'terminal')
  .option('-o, --output <path>', 'write results to file')
  .option('--ai', 'Enable AI validation (auto-detected if keys are set)')
  .option('--no-ai', 'Disable AI validation')
  .option('--ai-gating <mode>', 'AI gating mode (selective, high-only, all)', 'selective')
  .action(
    async (
      paths: string[],
      options: {
        format: 'terminal' | 'sarif' | 'github';
        output?: string;
        ai?: boolean;
        aiGating?: 'selective' | 'high-only' | 'all';
      }
    ) => {
      const targetDir = paths[0] || '.';
      if (options.ai === true) {
        const checkConfig = getAiConfig(targetDir);
        if (!checkConfig && process.stdin.isTTY) {
          const { runInteractiveSetup } = await import('./setup.js');
          await runInteractiveSetup(targetDir);
        }
      }

      const allFindings: Finding[] = [];
      const allSarifFindings: Finding[] = [];
      const allWarnings: string[] = [];
      let combinedExitCode = 0;

      for (const path of paths) {
        const result = await scan({
          targetPath: path,
          format: options.format === 'sarif' ? 'sarif' : 'terminal',
          ai: options.ai,
          aiGating: options.aiGating
        });

        allFindings.push(...result.findings);
        allSarifFindings.push(...result.sarifFindings);
        allWarnings.push(...result.warnings);
        if (result.exitCode !== 0) {
          combinedExitCode = 1;
        }
      }

      const uniqueWarnings = [...new Set(allWarnings)];
      for (const warning of uniqueWarnings) {
        process.stderr.write(`warning: ${warning}\n`);
      }

      if (options.format === 'sarif') {
        const sarif = JSON.stringify(findingsToSarif(allSarifFindings), null, 2);
        if (options.output) {
          await writeFile(resolve(options.output), sarif, 'utf8');
        } else {
          process.stdout.write(`${sarif}\n`);
        }
      } else if (options.format === 'github') {
        printGithubAnnotations(allFindings);
      } else {
        printFindings(allFindings);
      }

      process.exitCode = combinedExitCode;
    }
  );


void program.parseAsync(process.argv);

// ---------------------------------------------------------------------------
// Severity helpers
// ---------------------------------------------------------------------------

function colorSeverity(severity: string): string {
  const upper = severity.toUpperCase();
  switch (severity) {
    case 'critical':
      return pc.bgRed(pc.white(pc.bold(` ${upper} `)));
    case 'high':
      return pc.red(pc.bold(upper));
    case 'medium':
      return pc.yellow(pc.bold(upper));
    case 'low':
    default:
      return pc.cyan(pc.bold(upper));
  }
}

function engineBadge(engine: Finding['engine']): string {
  switch (engine) {
    case 'secret-scanner': return pc.magenta('[SECRET]');
    case 'sca':            return pc.red('[SCA]');
    case 'semgrep':        return pc.blue('[SEMGREP]');
    case 'custom-tree-sitter': return pc.green('[STATIC]');
    default:               return pc.dim('[?]');
  }
}

// ---------------------------------------------------------------------------
// Terminal output
// ---------------------------------------------------------------------------

function printFindings(findings: Finding[]): void {
  if (findings.length === 0) {
    process.stdout.write(pc.green(pc.bold('\n✔ No findings.\n')));
    return;
  }

  // Split by engine category for grouped display
  const secretFindings = findings.filter((f) => f.engine === 'secret-scanner');
  const scaFindings    = findings.filter((f) => f.engine === 'sca');
  const codeFindings   = findings.filter((f) => f.engine !== 'secret-scanner' && f.engine !== 'sca');

  if (secretFindings.length > 0) {
    process.stdout.write(pc.magenta(pc.bold(`\n🔑 Secret Leak Findings (${secretFindings.length}):\n`)));
    printBoxTable(secretFindings);
  }

  if (scaFindings.length > 0) {
    process.stdout.write(pc.red(pc.bold(`\n📦 Dependency Vulnerabilities / SCA (${scaFindings.length}):\n`)));
    printBoxTable(scaFindings);
  }

  if (codeFindings.length > 0) {
    process.stdout.write(pc.bold(`\n🔍 Code Analysis Findings (${codeFindings.length}):\n`));
    printBoxTable(codeFindings);
  }

  // AI validation cards (only for code findings)
  const aiFindings = codeFindings.filter((f) => f.aiConfirmed !== undefined);
  if (aiFindings.length > 0) {
    process.stdout.write(pc.bold('\nAI Validation Findings Cards:\n'));
    for (const finding of aiFindings) {
      printAiDetailCard(finding);
    }
  }

  // Summary line
  const critical = findings.filter((f) => f.severity === 'critical').length;
  const high     = findings.filter((f) => f.severity === 'high').length;
  const medium   = findings.filter((f) => f.severity === 'medium').length;
  const low      = findings.filter((f) => f.severity === 'low').length;
  process.stdout.write(
    `\n${pc.bold('Total:')} ${findings.length} finding(s) — ` +
    `${pc.bgRed(pc.white(pc.bold(` ${critical} CRITICAL `)))} ` +
    `${pc.red(pc.bold(`${high} HIGH`))} ` +
    `${pc.yellow(pc.bold(`${medium} MEDIUM`))} ` +
    `${pc.cyan(pc.bold(`${low} LOW`))}\n`
  );
}

function printBoxTable(findings: Finding[]): void {
  const headers = ['Engine', 'Severity', 'Location', 'Rule ID', 'Description'];

  const plainRows = findings.map((f) => {
    const relativePath = f.filePath.replace(resolve('.'), '');
    const loc = `${relativePath}:${f.line}`;
    const desc = f.message.substring(0, 55) + (f.message.length > 55 ? '…' : '');
    return [
      f.engine,
      f.severity.toUpperCase(),
      loc,
      f.ruleId,
      desc
    ];
  });

  const colWidths = headers.map((h, i) =>
    Math.max(h.length, ...plainRows.map((r) => (r[i] ?? '').length))
  );

  const sep = '|' + colWidths.map((w) => '-'.repeat(w + 2)).join('|') + '|\n';

  let output = sep;
  const headerCells = headers.map((h, i) => ` ${pc.bold(h.padEnd(colWidths[i]!))} `).join('|');
  output += '|' + headerCells + '|\n';
  output += sep;

  plainRows.forEach((row, idx) => {
    const finding = findings[idx]!;

    const engPlain  = row[0] ?? '';
    const sevPlain  = row[1] ?? '';
    const locPlain  = row[2] ?? '';
    const rulePlain = row[3] ?? '';
    const descPlain = row[4] ?? '';

    const engCell  = ` ${engineBadge(finding.engine)}${' '.repeat(Math.max(0, colWidths[0]! - engPlain.length))} `;
    const sevCell  = ` ${colorSeverity(finding.severity)}${' '.repeat(Math.max(0, colWidths[1]! - sevPlain.length))} `;
    const locCell  = ` ${pc.cyan(locPlain)}${' '.repeat(Math.max(0, colWidths[2]! - locPlain.length))} `;
    const ruleCell = ` ${rulePlain.padEnd(colWidths[3]!)} `;
    const descCell = ` ${descPlain.padEnd(colWidths[4]!)} `;

    output += `|${engCell}|${sevCell}|${locCell}|${ruleCell}|${descCell}|\n`;
    output += sep;
  });

  process.stdout.write(output);
}

function printAiDetailCard(finding: Finding): void {
  const statusText = finding.aiConfirmed ? 'Confirmed by AI' : 'Rejected by AI (False Positive)';
  const statusColor = finding.aiConfirmed ? pc.green(pc.bold(statusText)) : pc.red(pc.bold(statusText));

  const relativePath = finding.filePath.replace(resolve('.'), '');
  const attributes: Array<[string, string, string?]> = [
    ['Finding', finding.message],
    ['Severity', finding.severity.toUpperCase(), colorSeverity(finding.severity)],
    ['Location', `${relativePath}:${finding.line}`, pc.cyan(`${relativePath}:${finding.line}`)],
    ['Rule ID', finding.ruleId],
    ['AI Validation', statusText, statusColor]
  ];

  if (finding.explanation) {
    attributes.push(['Explanation', finding.explanation]);
  }
  if (finding.suggestedFixDiff) {
    attributes.push(['Suggested Fix', finding.suggestedFixDiff]);
  }

  const maxKeyLen = Math.max('Attribute'.length, ...attributes.map(([k]) => k.length));
  const maxValLen = 80;

  const border = '+' + '-'.repeat(maxKeyLen + 2) + '+' + '-'.repeat(maxValLen + 2) + '+\n';

  let output = border;
  output += '| ' + pc.bold('Attribute'.padEnd(maxKeyLen)) + ' | ' + pc.bold('Value'.padEnd(maxValLen)) + ' |\n';
  output += border;

  for (const [key, val, coloredVal] of attributes) {
    const keyCell = pc.bold(key.padEnd(maxKeyLen));
    const lines = wrapText(val, maxValLen);

    lines.forEach((line, idx) => {
      const kDisplay = idx === 0 ? keyCell : ' '.repeat(maxKeyLen);
      let vDisplay = line.padEnd(maxValLen);
      if (idx === 0 && coloredVal) {
        vDisplay = coloredVal + ' '.repeat(Math.max(0, maxValLen - line.length));
      } else if (key === 'Suggested Fix') {
        vDisplay = pc.dim(line).padEnd(maxValLen + (pc.dim(line).length - line.length));
      }
      output += `| ${kDisplay} | ${vDisplay} |\n`;
    });
  }

  output += border;
  process.stdout.write(output + '\n');
}

function wrapText(text: string, maxWidth: number): string[] {
  const lines: string[] = [];
  const rawLines = text.split(/\r?\n/);

  for (const rawLine of rawLines) {
    if (rawLine.length <= maxWidth) {
      lines.push(rawLine);
    } else {
      const words = rawLine.split(' ');
      let currentLine = '';
      for (const word of words) {
        if ((currentLine + ' ' + word).trim().length > maxWidth) {
          if (currentLine) lines.push(currentLine.trim());
          currentLine = word;
        } else {
          currentLine += (currentLine ? ' ' : '') + word;
        }
      }
      if (currentLine) lines.push(currentLine.trim());
    }
  }

  return lines.length > 0 ? lines : [''];
}

function printGithubAnnotations(findings: Finding[]): void {
  for (const finding of findings) {
    const severityAnnotation = (finding.severity === 'high' || finding.severity === 'critical') ? 'error' : 'warning';
    let message = `[${finding.engine.toUpperCase()}][${finding.severity.toUpperCase()}] ${finding.message}`;
    if (finding.aiConfirmed && finding.explanation) {
      message += ` | AI: ${finding.explanation}`;
    }
    const col = finding.column || 1;
    process.stdout.write(`::${severityAnnotation} file=${finding.filePath},line=${finding.line},col=${col}::${message}\n`);
  }
}
