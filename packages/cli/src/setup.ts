import readline from 'node:readline';
import { promises as fs } from 'node:fs';
import { join } from 'node:path';
import { homedir } from 'node:os';
import pc from 'picocolors';

export function promptQuestion(query: string): Promise<string> {
  const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout
  });
  return new Promise((resolve) => {
    rl.question(query, (answer) => {
      rl.close();
      resolve(answer.trim());
    });
  });
}

export async function runInteractiveSetup(targetPath: string): Promise<boolean> {
  if (!process.stdin.isTTY) {
    return false;
  }

  process.stdout.write(pc.bold(pc.cyan('\n=== Guardrail AI Validation Setup ===\n')));
  process.stdout.write('This setup will save your credentials to automatically enable AI validation.\n\n');

  const confirm = await promptQuestion('Would you like to configure AI validation now? (y/N): ');
  if (confirm.toLowerCase() !== 'y' && confirm.toLowerCase() !== 'yes') {
    process.stdout.write('Setup skipped.\n\n');
    return false;
  }

  process.stdout.write('\nSelect AI Provider:\n');
  process.stdout.write('  1) Anthropic Claude (requires ANTHROPIC_API_KEY)\n');
  process.stdout.write('  2) OpenAI / OpenRouter / Custom (requires API Key or Base URL)\n');
  const providerSelection = await promptQuestion('Choose provider [1-2, default: 2]: ');
  const provider = providerSelection === '1' ? 'anthropic' : 'openai';

  let apiBase = '';
  if (provider === 'openai') {
    apiBase = await promptQuestion('Enter API Base URL (optional, e.g. https://openrouter.ai/api/v1): ');
  }

  const apiKey = await promptQuestion('Enter your API Key: ');
  if (!apiKey) {
    process.stdout.write(pc.red('Error: API Key is required to enable AI validation.\n\n'));
    return false;
  }

  const model = await promptQuestion(`Enter Model Name (optional, defaults to ${provider === 'anthropic' ? 'claude-3-5-haiku-20241022' : 'gpt-4o-mini'}): `);

  const globalConfirm = await promptQuestion('Save configuration globally for all projects? (Y/n): ');
  const isGlobal = globalConfirm.toLowerCase() !== 'n' && globalConfirm.toLowerCase() !== 'no';

  const config = {
    provider,
    apiKey,
    ...(apiBase ? { apiBase } : {}),
    ...(model ? { model } : {})
  };

  const configDir = isGlobal
    ? join(homedir(), '.guardrail')
    : join(targetPath, '.guardrail');
  const configPath = join(configDir, 'config.json');

  try {
    await fs.mkdir(configDir, { recursive: true });
    await fs.writeFile(configPath, JSON.stringify(config, null, 2), 'utf8');
    process.stdout.write(pc.green(pc.bold(`\n✔ Configuration successfully written to ${configPath}\n\n`)));
    return true;
  } catch (err) {
    process.stdout.write(pc.red(`\n✘ Error saving configuration: ${(err as Error).message}\n\n`));
    return false;
  }
}

