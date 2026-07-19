import { promises as fs } from 'node:fs';
import { join, resolve } from 'node:path';
import type { Finding } from './types.js';

interface PackageJson {
  name?: string;
  dependencies?: Record<string, string>;
  devDependencies?: Record<string, string>;
}

interface OsvVulnerability {
  id: string;
  aliases?: string[];
  summary?: string;
  severity?: Array<{ type: string; score: string }>;
}

interface OsvQueryResult {
  vulns?: OsvVulnerability[];
}

interface OsvBatchResponse {
  results?: OsvQueryResult[];
}

export interface ScaRunResult {
  findings: Finding[];
  warnings: string[];
}

/**
 * Extract the first concrete semver triple from a version specifier.
 * e.g. "^4.17.20" → "4.17.20", ">=1.0.0 <2.0.0" → "1.0.0", "latest" → null
 */
function extractConcreteVersion(spec: string): string | null {
  const match = spec.replace(/[^0-9.]*/,'').match(/^(\d+\.\d+\.\d+)/);
  return match ? match[1] ?? null : null;
}

/**
 * Map OSV severity data (CVSS score) to our internal severity.
 */
function mapOsvSeverity(vuln: OsvVulnerability): Finding['severity'] {
  for (const sev of vuln.severity ?? []) {
    if (sev.type === 'CVSS_V3' || sev.type === 'CVSS_V2') {
      const score = parseFloat(sev.score);
      if (!isNaN(score)) {
        if (score >= 9.0) return 'critical';
        if (score >= 7.0) return 'high';
        if (score >= 4.0) return 'medium';
        return 'low';
      }
    }
  }
  // Any confirmed CVE defaults to high when CVSS is missing
  return 'high';
}

async function findPackageJsonFiles(targetPath: string): Promise<string[]> {
  const found: string[] = [];
  let stat;
  try {
    stat = await fs.stat(targetPath);
  } catch {
    return found;
  }

  if (stat.isFile()) {
    if (targetPath.endsWith('package.json')) found.push(targetPath);
    return found;
  }

  const SKIP_DIRS = new Set(['node_modules', '.git', 'dist', 'build', 'coverage']);
  const stack = [targetPath];

  while (stack.length > 0) {
    const current = stack.pop()!;
    let entries;
    try {
      entries = await fs.readdir(current, { withFileTypes: true });
    } catch {
      continue;
    }

    for (const entry of entries) {
      if (SKIP_DIRS.has(entry.name)) continue;
      const fullPath = join(current, entry.name);
      if (entry.isDirectory()) {
        stack.push(fullPath);
      } else if (entry.isFile() && entry.name === 'package.json') {
        found.push(resolve(fullPath));
      }
    }
  }

  return found;
}

interface ResolvedDep {
  name: string;
  version: string;
  pkgJsonPath: string;
}

export async function runScaScan(targetPath: string): Promise<ScaRunResult> {
  const pkgFiles = await findPackageJsonFiles(targetPath);
  if (pkgFiles.length === 0) return { findings: [], warnings: [] };

  const rawDeps: ResolvedDep[] = [];

  for (const pkgPath of pkgFiles) {
    let pkg: PackageJson;
    try {
      const content = await fs.readFile(pkgPath, 'utf8');
      pkg = JSON.parse(content) as PackageJson;
    } catch {
      continue;
    }

    const allDeps: Record<string, string> = {
      ...pkg.dependencies,
      ...pkg.devDependencies
    };

    for (const [name, versionSpec] of Object.entries(allDeps)) {
      const version = extractConcreteVersion(versionSpec);
      if (version) {
        rawDeps.push({ name, version, pkgJsonPath: pkgPath });
      }
    }
  }

  if (rawDeps.length === 0) return { findings: [], warnings: [] };

  // Deduplicate by name@version (same package may appear in multiple package.json files)
  const dedupMap = new Map<string, ResolvedDep>();
  for (const dep of rawDeps) {
    const key = `${dep.name}@${dep.version}`;
    if (!dedupMap.has(key)) dedupMap.set(key, dep);
  }
  const deps = [...dedupMap.values()];

  // Build OSV.dev batch request
  const queries = deps.map((d) => ({
    package: { name: d.name, ecosystem: 'npm' },
    version: d.version
  }));

  let osvResponse: OsvBatchResponse;
  try {
    const res = await fetch('https://api.osv.dev/v1/querybatch', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ queries }),
      signal: AbortSignal.timeout(20_000)
    });

    if (!res.ok) {
      return {
        findings: [],
        warnings: [`SCA: OSV.dev API returned HTTP ${res.status}. Dependency vulnerability scan skipped.`]
      };
    }

    osvResponse = (await res.json()) as OsvBatchResponse;
  } catch (err) {
    const msg = (err as Error).message;
    return {
      findings: [],
      warnings: [`SCA: Could not reach OSV.dev (${msg}). Dependency vulnerability scan skipped.`]
    };
  }

  const findings: Finding[] = [];
  const results = osvResponse.results ?? [];

  for (let i = 0; i < deps.length; i++) {
    const dep = deps[i]!;
    const result = results[i];
    if (!result?.vulns || result.vulns.length === 0) continue;

    for (const vuln of result.vulns) {
      const cveId = vuln.aliases?.find((a) => a.startsWith('CVE-')) ?? vuln.id;
      const advisoryUrl = `https://osv.dev/vulnerability/${vuln.id}`;
      const summary = vuln.summary ?? 'Known vulnerability';

      findings.push({
        ruleId: 'sca.vulnerable-dependency',
        message: `${dep.name}@${dep.version} — ${cveId}: ${summary} → ${advisoryUrl}`,
        severity: mapOsvSeverity(vuln),
        engine: 'sca',
        filePath: dep.pkgJsonPath,
        line: 1,
        column: 1,
        fix: `Upgrade ${dep.name} to a patched version. Check advisory: ${advisoryUrl}`
      });
    }
  }

  return { findings, warnings: [] };
}
