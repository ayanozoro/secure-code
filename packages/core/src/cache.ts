import { promises as fs } from 'node:fs';
import { join } from 'node:path';
import { createHash } from 'node:crypto';
import type { AiValidation } from './types.js';

export function computeCacheKey(ruleId: string, filePath: string, snippet: string): string {
  const content = `${ruleId}:${filePath}:${snippet}`;
  return createHash('sha256').update(content).digest('hex');
}

function getCacheDir(targetPath: string): string {
  return join(targetPath, '.guardrail', 'cache');
}

export async function getCachedValidation(
  cacheDirParent: string,
  key: string
): Promise<AiValidation | null> {
  const cacheDir = getCacheDir(cacheDirParent);
  const cachePath = join(cacheDir, `${key}.json`);

  try {
    const data = await fs.readFile(cachePath, 'utf8');
    return JSON.parse(data) as AiValidation;
  } catch {
    return null;
  }
}

export async function setCachedValidation(
  cacheDirParent: string,
  key: string,
  validation: AiValidation
): Promise<void> {
  const cacheDir = getCacheDir(cacheDirParent);
  const cachePath = join(cacheDir, `${key}.json`);

  try {
    await fs.mkdir(cacheDir, { recursive: true });
    await fs.writeFile(cachePath, JSON.stringify(validation, null, 2), 'utf8');
  } catch {
    // Ignore cache write errors gracefully
  }
}
