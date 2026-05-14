import path from 'node:path';
import semver from 'semver';
import { findFiles } from '../walk.js';
import { LOCKFILE_PARSERS } from './lockfile-parsers.js';

const LOCKFILE_NAMES = Object.keys(LOCKFILE_PARSERS);

/**
 * Lockfile scanner. Walks the given root directory, finds supported lockfiles,
 * parses each, cross-references every (ecosystem, name, version) against the
 * IoC `indicators.package` list (via the `packages_by_ecosystem_name` index).
 *
 * @param {Object} iocs — the full iocs.json document
 * @param {{ root?: string, depth?: number, ecosystem?: 'npm'|'pypi' }} [options]
 * @returns {Promise<{
 *   findings: Array<{ indicator: Object, artifact: { lockfile: string, name: string, version: string } }>,
 *   scanned: { lockfiles_found: number, packages_checked: number },
 *   errors: string[]
 * }>}
 */
export async function scan(iocs, options = {}) {
  const root = options.root ?? process.cwd();
  const depth = options.depth ?? 5;
  const ecosystemFilter = options.ecosystem;

  const lockfiles = await findFiles(root, { targets: LOCKFILE_NAMES, depth });
  const findings = [];
  const errors = [];
  let packagesChecked = 0;

  const packageIndicators = iocs?.indicators?.package ?? [];
  const indicatorById = new Map(packageIndicators.map((ind) => [ind.id, ind]));
  const lookupIndex = iocs?.indexes?.packages_by_ecosystem_name ?? {};

  for (const lockfile of lockfiles) {
    const basename = path.basename(lockfile);
    const parser = LOCKFILE_PARSERS[basename];
    if (!parser) continue;

    let entries;
    try {
      entries = await parser(lockfile);
    } catch (err) {
      errors.push(`failed to parse ${lockfile}: ${err.message}`);
      continue;
    }

    for (const entry of entries) {
      if (ecosystemFilter && entry.ecosystem !== ecosystemFilter) continue;
      packagesChecked += 1;

      const key = `${entry.ecosystem}:${entry.name.toLowerCase()}`;
      const candidateIds = lookupIndex[key];
      if (!candidateIds || candidateIds.length === 0) continue;

      for (const id of candidateIds) {
        const indicator = indicatorById.get(id);
        if (!indicator) continue;
        if (matchesVersion(entry.version, indicator)) {
          findings.push({
            indicator,
            artifact: {
              lockfile: path.relative(root, lockfile),
              name: entry.name,
              version: entry.version,
            },
          });
        }
      }
    }
  }

  return {
    findings,
    scanned: { lockfiles_found: lockfiles.length, packages_checked: packagesChecked },
    errors,
  };
}

function matchesVersion(installedVersion, indicator) {
  const spec = indicator.versions;
  if (!spec) return true; // no version constraint = match any version of this name

  // npm/semver
  if (indicator.ecosystem === 'npm' || indicator.version_range === 'semver') {
    if (indicator.version_range === 'exact') return installedVersion === spec;
    try {
      // Coerce; lockfiles sometimes have non-canonical versions (e.g. "1.2.3-rc.1+build")
      if (semver.satisfies(installedVersion, spec, { includePrerelease: true })) return true;
      // Also try exact equality as a fallback
      if (installedVersion === spec) return true;
    } catch {
      return installedVersion === spec;
    }
    return false;
  }

  // pypi / pep440 — v0.1 only supports exact match for safety; pep440 ranges deferred to v0.2
  if (indicator.ecosystem === 'pypi') {
    return installedVersion === spec;
  }

  // Default: exact equality
  return installedVersion === spec;
}
