import { spawn } from 'node:child_process';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import type { Finding } from './types.js';

interface SemgrepJsonResult {
  check_id?: string;
  path?: string;
  start?: {
    line?: number;
    col?: number;
  };
  extra?: {
    message?: string;
    metadata?: {
      severity?: string;
    };
  };
}

interface SemgrepJsonOutput {
  results?: SemgrepJsonResult[];
}

export interface SemgrepRunResult {
  findings: Finding[];
  warnings: string[];
}

export async function runSemgrep(targetPath: string): Promise<SemgrepRunResult> {
  const currentDir = resolve(fileURLToPath(new URL('.', import.meta.url)));
  // Point at the whole rules/semgrep directory — any .yml file inside is loaded automatically
  const rulesPath = resolve(currentDir, '../rules/semgrep');
  const semgrepArgs = ['--config', rulesPath, '--json', '--quiet', targetPath];
  const execution = await runSemgrepWithFallbacks(semgrepArgs);

  if (execution.notInstalled) {
    return {
      findings: [],
      warnings: ['Semgrep is not installed or not available on PATH. Static Semgrep checks were skipped.']
    };
  }

  if (!execution.stdout) {
    if (execution.exitCode !== 0) {
      return {
        findings: [],
        warnings: [`Semgrep exited with code ${execution.exitCode}.`]
      };
    }

    return { findings: [], warnings: [] };
  }

  let parsed: SemgrepJsonOutput;
  try {
    parsed = JSON.parse(execution.stdout) as SemgrepJsonOutput;
  } catch {
    return {
      findings: [],
      warnings: ['Semgrep output was not valid JSON.']
    };
  }

  const findings = (parsed.results ?? [])
    .map((result): Finding | undefined => {
      if (!result.path || !result.check_id || !result.start?.line) {
        return undefined;
      }

      return {
        ruleId: result.check_id,
        message: result.extra?.message ?? 'Security finding.',
        severity: mapSemgrepSeverity(result.extra?.metadata?.severity),
        engine: 'semgrep',
        filePath: resolve(result.path),
        line: result.start.line,
        column: result.start.col ?? 1
      };
    })
    .filter((value): value is Finding => Boolean(value));

  return { findings, warnings: [] };
}

function mapSemgrepSeverity(input?: string): Finding['severity'] {
  const normalized = (input ?? '').toLowerCase();
  if (normalized === 'error') {
    return 'high';
  }
  if (normalized === 'warning') {
    return 'medium';
  }
  if (normalized === 'info') {
    return 'low';
  }
  return 'medium';
}

interface SemgrepExecution {
  stdout: string;
  stderr: string;
  exitCode: number;
  notInstalled: boolean;
}

function runSemgrepProcess(args: string[]): Promise<SemgrepExecution> {
  return runCommand('semgrep', args);
}

async function runSemgrepWithFallbacks(args: string[]): Promise<SemgrepExecution> {
  const direct = await runSemgrepProcess(args);
  if (!direct.notInstalled) {
    return direct;
  }

  const pyFallback = await runCommand('py', ['-m', 'semgrep', ...args]);
  if (!pyFallback.notInstalled) {
    return pyFallback;
  }

  const pythonFallback = await runCommand('python', ['-m', 'semgrep', ...args]);
  if (!pythonFallback.notInstalled) {
    return pythonFallback;
  }

  return direct;
}

function runCommand(command: string, args: string[]): Promise<SemgrepExecution> {
  return new Promise((resolvePromise) => {
    const child = spawn(command, args, { shell: false });
    const stdoutChunks: string[] = [];
    const stderrChunks: string[] = [];
    let notInstalled = false;

    child.stdout.on('data', (chunk) => {
      stdoutChunks.push(String(chunk));
    });

    child.stderr.on('data', (chunk) => {
      stderrChunks.push(String(chunk));
    });

    child.on('error', (error) => {
      if ((error as NodeJS.ErrnoException).code === 'ENOENT') {
        notInstalled = true;
      }
    });

    child.on('close', (code) => {
      resolvePromise({
        stdout: stdoutChunks.join(''),
        stderr: stderrChunks.join(''),
        exitCode: code ?? 1,
        notInstalled
      });
    });
  });
}
