import { spawn } from 'node:child_process';
import semver from 'semver';
import { detectPackageManager, resolveInstallTree } from './scanners/install-tree.js';

/**
 * Cross-reference resolved install tree against IoC package indicators.
 *
 * @param {Array<{name: string, version: string, ecosystem: 'npm'}>} resolved
 * @param {Object} iocs
 * @returns {Array<{indicator: Object, artifact: {name: string, version: string, source: 'install-tree'}}>}
 */
export function matchTreeAgainstIocs(resolved, iocs) {
  const lookup = iocs?.indexes?.packages_by_ecosystem_name ?? {};
  const indicators = iocs?.indicators?.package ?? [];
  const byId = new Map(indicators.map((i) => [i.id, i]));
  const findings = [];

  for (const entry of resolved) {
    const key = `${entry.ecosystem}:${entry.name.toLowerCase()}`;
    const ids = lookup[key];
    if (!ids?.length) continue;
    for (const id of ids) {
      const ind = byId.get(id);
      if (!ind) continue;
      if (versionMatches(entry.version, ind)) {
        findings.push({
          indicator: ind,
          artifact: { name: entry.name, version: entry.version, source: 'install-tree' },
        });
      }
    }
  }
  return findings;
}

function versionMatches(installed, indicator) {
  const spec = indicator.versions;
  if (!spec) return true;
  if (indicator.version_range === 'exact') return installed === spec;
  if (indicator.version_range === 'list') return spec.split('||').includes(installed);
  if (indicator.ecosystem === 'npm') {
    if (installed === spec) return true;
    try {
      return semver.satisfies(installed, spec, { includePrerelease: true });
    } catch {
      return installed === spec;
    }
  }
  return installed === spec;
}

/**
 * Run the install-interception flow:
 *   1. Detect package manager
 *   2. Resolve the proposed install tree (without running scripts)
 *   3. Match against IoC package indicators
 *   4. If clean: pass through to the real install
 *   5. If finding: refuse, print findings, exit non-zero
 *
 * @param {{
 *   pkgs: string[],
 *   iocs: Object,
 *   cwd?: string,
 *   pm?: 'npm'|'pnpm'|'yarn',
 *   resolveFn?: typeof resolveInstallTree,
 *   passThroughFn?: (pm: string, pkgs: string[], cwd: string) => Promise<{code: number}>,
 *   onProgress?: (event: string, data: Object) => void
 * }} args
 * @returns {Promise<{
 *   pm: string,
 *   resolvedCount: number,
 *   findings: Array,
 *   passedThrough: boolean,
 *   exitCode: number
 * }>}
 */
export async function runInterceptor(args) {
  const cwd = args.cwd ?? process.cwd();
  const pm = args.pm ?? detectPackageManager(cwd);
  const resolveFn = args.resolveFn ?? resolveInstallTree;
  const passThroughFn = args.passThroughFn ?? defaultPassThrough;
  const onProgress = args.onProgress ?? (() => {});

  onProgress('detect', { pm });

  let resolved;
  try {
    resolved = await resolveFn({ pm, pkgs: args.pkgs, cwd });
  } catch (err) {
    return {
      pm,
      resolvedCount: 0,
      findings: [],
      passedThrough: false,
      exitCode: 2,
      error: `failed to resolve install tree: ${err.message}`,
    };
  }
  onProgress('resolved', { count: resolved.length });

  const findings = matchTreeAgainstIocs(resolved, args.iocs);
  onProgress('scanned', { findings: findings.length });

  if (findings.length > 0) {
    return { pm, resolvedCount: resolved.length, findings, passedThrough: false, exitCode: 1 };
  }

  onProgress('passthrough', {});
  const { code } = await passThroughFn(pm, args.pkgs, cwd);
  return { pm, resolvedCount: resolved.length, findings: [], passedThrough: true, exitCode: code };
}

function defaultPassThrough(pm, pkgs, cwd) {
  return new Promise((resolve) => {
    const args = pm === 'yarn' ? ['add', ...pkgs] : ['install', ...pkgs];
    const child = spawn(pm, args, { cwd, stdio: 'inherit' });
    child.on('close', (code) => resolve({ code: code ?? 0 }));
  });
}
