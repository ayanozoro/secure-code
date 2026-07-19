import { exec } from 'node:child_process';
import { promises as fs } from 'node:fs';
import { resolve, join } from 'node:path';
import pc from 'picocolors';
import { getAiConfig } from '@securecode/core';

export async function runDoctor(): Promise<number> {
  process.stdout.write(pc.bold('\nGuardrail Doctor Diagnostics:\n'));
  process.stdout.write(pc.dim('----------------------------\n'));

  let hasErrors = false;
  let hasWarnings = false;

  // 1. Check Node.js Version
  const nodeVersion = process.version;
  const major = parseInt(nodeVersion.slice(1).split('.')[0], 10);
  if (major >= 18) {
    process.stdout.write(`${pc.green('✔')} ${pc.bold('Node.js:')} Detected version ${nodeVersion} (>= v18.0.0 required)\n`);
  } else {
    process.stdout.write(`${pc.red('✘')} ${pc.bold('Node.js:')} Detected version ${nodeVersion}. Guardrail requires Node.js >= v18.0.0\n`);
    hasErrors = true;
  }

  // 2. Check Semgrep CLI
  const semgrepVersion = await checkSemgrep();
  if (semgrepVersion) {
    process.stdout.write(`${pc.green('✔')} ${pc.bold('Semgrep:')} CLI is installed (${semgrepVersion})\n`);
  } else {
    process.stdout.write(`${pc.yellow('⚠')} ${pc.bold('Semgrep:')} CLI was not found directly on PATH. Static checks might be skipped or fall back to python wrappers.\n`);
    hasWarnings = true;
  }

  // 3. Check AI Configuration
  const aiConfig = getAiConfig(resolve('.'));
  if (aiConfig) {
    process.stdout.write(`${pc.green('✔')} ${pc.bold('AI Config:')} Provider '${aiConfig.provider}' is active using model '${aiConfig.model}'\n`);
  } else {
    process.stdout.write(`${pc.yellow('⚠')} ${pc.bold('AI Config:')} No credentials (OPENAI_API_KEY / ANTHROPIC_API_KEY) found. AI validation is disabled (running in static-only mode).\n`);
    hasWarnings = true;
  }

  // 4. Check Cache Folder Writeability
  const cacheDir = resolve('.', '.guardrail', 'cache');
  const cacheOk = await checkCacheDir(cacheDir);
  if (cacheOk) {
    process.stdout.write(`${pc.green('✔')} ${pc.bold('Cache:')} Cache directory is writeable (${cacheDir})\n`);
  } else {
    process.stdout.write(`${pc.yellow('⚠')} ${pc.bold('Cache:')} Cache directory is not active or writeable. Scanning will still work, but results will not be cached.\n`);
    hasWarnings = true;
  }

  process.stdout.write(pc.dim('----------------------------\n'));

  if (!aiConfig && process.stdin.isTTY) {
    const { runInteractiveSetup } = await import('./setup.js');
    const setupCompleted = await runInteractiveSetup(resolve('.'));
    if (setupCompleted) {
      const newConfig = getAiConfig(resolve('.'));
      if (newConfig) {
        process.stdout.write(pc.green(pc.bold('✔ Diagnostics re-evaluation: AI validation is now active!\n\n')));
        hasWarnings = false;
      }
    }
  }

  if (hasErrors) {
    process.stdout.write(pc.red(pc.bold('Status: Health Check failed. Please resolve the errors above.\n\n')));
    return 1;
  } else if (hasWarnings) {
    process.stdout.write(pc.yellow(pc.bold('Status: Health Check completed with warnings.\n\n')));
    return 0;
  } else {
    process.stdout.write(pc.green(pc.bold('Status: All OK. Guardrail is healthy and ready to scan!\n\n')));
    return 0;
  }

}

function checkSemgrep(): Promise<string | null> {
  return new Promise((res) => {
    exec('semgrep --version', (err, stdout) => {
      if (err) {
        res(null);
      } else {
        res(stdout.trim());
      }
    });
  });
}

async function checkCacheDir(dir: string): Promise<boolean> {
  try {
    await fs.mkdir(dir, { recursive: true });
    // Write a temp file and delete it to verify permissions
    const tempFile = join(dir, '.doctor-write-test');
    await fs.writeFile(tempFile, 'test', 'utf8');
    await fs.unlink(tempFile);
    return true;
  } catch {
    return false;
  }
}
