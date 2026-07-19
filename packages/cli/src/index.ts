#!/usr/bin/env node
import { Command } from 'commander';
import { writeFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { findingsToSarif, scan, type Finding } from '@securecode/core';

const program = new Command();

program
  .name('guardrail')
  .description('Local hybrid static + AI security scanner for JS/TS codebases')
  .version('0.1.0');

program
  .command('scan')
  .argument('<path>', 'path to a file or directory')
  .option('-f, --format <format>', 'output format', 'terminal')
  .option('-o, --output <path>', 'write results to file')
  .action(async (path: string, options: { format: 'terminal' | 'sarif'; output?: string }) => {
    const result = await scan({ targetPath: path, format: options.format });
    for (const warning of result.warnings) {
      process.stderr.write(`warning: ${warning}\n`);
    }

    if (options.format === 'sarif') {
      const sarif = JSON.stringify(findingsToSarif(result.sarifFindings), null, 2);
      if (options.output) {
        await writeFile(resolve(options.output), sarif, 'utf8');
      } else {
        process.stdout.write(`${sarif}\n`);
      }
    } else {
      printFindings(result.findings);
    }

    process.exitCode = result.exitCode;
  });

void program.parseAsync(process.argv);

function printFindings(findings: Finding[]): void {
  if (findings.length === 0) {
    process.stdout.write('No findings.\n');
    return;
  }

  for (const finding of findings) {
    process.stdout.write(`[${finding.severity.toUpperCase()}] ${finding.filePath}:${finding.line} ${finding.message}\n`);
  }
}
