import { readFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const POPULAR_PATH = path.resolve(HERE, '../data/popular-packages.json');

const NPM_REGISTRY = 'https://registry.npmjs.org';
const PYPI_REGISTRY = 'https://pypi.org/pypi';
const FETCH_TIMEOUT_MS = 6000;

export const DEFAULT_COOLDOWN_HOURS = 48;
const NEW_PACKAGE_DAYS = 7;

let popularCache = null;

async function loadPopular() {
  if (!popularCache) {
    popularCache = JSON.parse(await readFile(POPULAR_PATH, 'utf8'));
  }
  return popularCache;
}

/**
 * Parse a package spec as passed to an installer into { name, spec }.
 * Handles npm scoped packages ("@scope/name@^1.2.3"), pip version pins
 * ("requests==2.31.0"), and pip extras ("uvicorn[standard]").
 *
 * @param {string} raw
 * @param {'npm'|'pypi'} ecosystem
 * @returns {{ name: string, spec: string|null }}
 */
export function parsePackageSpec(raw, ecosystem) {
  if (ecosystem === 'pypi') {
    // strip extras, then split on the first comparator
    const noExtras = raw.replace(/\[[^\]]*\]/, '');
    const m = noExtras.match(/^([A-Za-z0-9._-]+)\s*(?:(===|==|~=|!=|>=|<=|>|<)\s*(.+))?$/);
    if (!m) return { name: noExtras, spec: null };
    return { name: m[1].toLowerCase(), spec: m[3] ? `${m[2]}${m[3].trim()}` : null };
  }
  // npm: the last "@" that isn't the leading scope marker separates the range
  const at = raw.lastIndexOf('@');
  if (at > 0) {
    return { name: raw.slice(0, at), spec: raw.slice(at + 1) || null };
  }
  return { name: raw, spec: null };
}

/**
 * Optimal-string-alignment distance (Levenshtein + adjacent transposition),
 * bailing out early once distance exceeds `max`. Transpositions count as one
 * edit because they're the most common typosquat pattern ("lodahs"/"lodash").
 */
export function levenshtein(a, b, max = 2) {
  if (a === b) return 0;
  if (Math.abs(a.length - b.length) > max) return max + 1;
  let prevPrev = null;
  let prev = Array.from({ length: b.length + 1 }, (_, i) => i);
  for (let i = 1; i <= a.length; i++) {
    const cur = [i];
    let rowMin = i;
    for (let j = 1; j <= b.length; j++) {
      cur[j] = Math.min(
        prev[j] + 1,
        cur[j - 1] + 1,
        prev[j - 1] + (a[i - 1] === b[j - 1] ? 0 : 1),
      );
      if (i > 1 && j > 1 && a[i - 1] === b[j - 2] && a[i - 2] === b[j - 1]) {
        cur[j] = Math.min(cur[j], prevPrev[j - 2] + 1);
      }
      if (cur[j] < rowMin) rowMin = cur[j];
    }
    if (rowMin > max) return max + 1;
    prevPrev = prev;
    prev = cur;
  }
  return prev[b.length];
}

/**
 * Check a package name against the bundled popular-package list for
 * typosquat / slopsquat similarity. A name that IS popular is fine; a name
 * within edit distance 1 of a popular name (or a popular name with a
 * "js"/"-js"/"node-" affix bolted on) is suspicious.
 *
 * @returns {Promise<{ suspicious: boolean, lookalikeOf?: string, reason?: string }>}
 */
export async function checkTyposquat(name, ecosystem) {
  const popular = await loadPopular();
  const list = popular[ecosystem] ?? [];
  const set = new Set(list);
  const lower = name.toLowerCase();
  if (set.has(lower)) return { suspicious: false };

  // Scoped npm names: compare the bare name too ("@types/lodash" → "lodash" is fine,
  // but "@lodash/core" imitating "lodash" is caught by the full-name pass below).
  for (const pop of list) {
    if (levenshtein(lower, pop, 1) === 1) {
      return { suspicious: true, lookalikeOf: pop, reason: `one edit away from popular package "${pop}"` };
    }
    if (lower === `${pop}js` || lower === `${pop}-js` || lower === `node-${pop}` || lower === `${pop}-node`) {
      return { suspicious: true, lookalikeOf: pop, reason: `popular package "${pop}" with a js/node affix — classic squat pattern` };
    }
  }
  return { suspicious: false };
}

/**
 * Fetch registry metadata for one package. Returns null on any network
 * failure (callers fail open — a broken network must never block installs).
 *
 * @returns {Promise<null | {
 *   exists: boolean,
 *   createdAt?: Date,
 *   latestVersion?: string,
 *   latestPublishedAt?: Date,
 *   versionPublishedAt?: Date,   // for the specific requested version, if pinned
 *   previousStableVersion?: string, // newest version older than the cooldown window
 *   hasInstallScript?: boolean,
 * }>}
 */
export async function fetchRegistryMetadata(name, spec, ecosystem, { fetchFn = fetch, cooldownHours = DEFAULT_COOLDOWN_HOURS } = {}) {
  try {
    if (ecosystem === 'pypi') return await fetchPypi(name, spec, fetchFn, cooldownHours);
    return await fetchNpm(name, spec, fetchFn, cooldownHours);
  } catch {
    return null;
  }
}

async function fetchNpm(name, spec, fetchFn, cooldownHours) {
  const resp = await fetchFn(`${NPM_REGISTRY}/${encodeURIComponent(name).replace('%40', '@')}`, {
    signal: AbortSignal.timeout(FETCH_TIMEOUT_MS),
  });
  if (resp.status === 404) return { exists: false };
  if (!resp.ok) return null;
  const doc = await resp.json();

  const time = doc.time ?? {};
  const latestVersion = doc['dist-tags']?.latest;
  const latest = latestVersion ? doc.versions?.[latestVersion] : undefined;
  const cutoff = Date.now() - cooldownHours * 3600 * 1000;

  // Newest version whose publish date is older than the cooldown window —
  // what we suggest the agent installs instead.
  let previousStableVersion;
  let previousStableAt = 0;
  for (const [v, iso] of Object.entries(time)) {
    if (v === 'created' || v === 'modified') continue;
    const t = Date.parse(iso);
    if (t < cutoff && t > previousStableAt && doc.versions?.[v] && !v.includes('-')) {
      previousStableAt = t;
      previousStableVersion = v;
    }
  }

  return {
    exists: true,
    createdAt: time.created ? new Date(time.created) : undefined,
    latestVersion,
    latestPublishedAt: latestVersion && time[latestVersion] ? new Date(time[latestVersion]) : undefined,
    versionPublishedAt: spec && time[spec] ? new Date(time[spec]) : undefined,
    previousStableVersion,
    hasInstallScript: Boolean(
      latest?.scripts && ['preinstall', 'install', 'postinstall'].some((k) => latest.scripts[k]),
    ),
  };
}

async function fetchPypi(name, spec, fetchFn, cooldownHours) {
  const resp = await fetchFn(`${PYPI_REGISTRY}/${encodeURIComponent(name)}/json`, {
    signal: AbortSignal.timeout(FETCH_TIMEOUT_MS),
  });
  if (resp.status === 404) return { exists: false };
  if (!resp.ok) return null;
  const doc = await resp.json();

  const releases = doc.releases ?? {};
  const cutoff = Date.now() - cooldownHours * 3600 * 1000;
  let createdAt;
  let previousStableVersion;
  let previousStableAt = 0;
  const uploadOf = (files) => {
    let earliest;
    for (const f of files ?? []) {
      const t = Date.parse(f.upload_time_iso_8601 ?? f.upload_time);
      if (!Number.isNaN(t) && (earliest === undefined || t < earliest)) earliest = t;
    }
    return earliest;
  };
  for (const [v, files] of Object.entries(releases)) {
    const t = uploadOf(files);
    if (t === undefined) continue;
    if (createdAt === undefined || t < createdAt) createdAt = t;
    if (t < cutoff && t > previousStableAt) {
      previousStableAt = t;
      previousStableVersion = v;
    }
  }

  const latestVersion = doc.info?.version;
  const pinned = spec?.startsWith('==') ? spec.replace(/^==/, '') : null;
  return {
    exists: true,
    createdAt: createdAt !== undefined ? new Date(createdAt) : undefined,
    latestVersion,
    latestPublishedAt: latestVersion ? asDate(uploadOf(releases[latestVersion])) : undefined,
    versionPublishedAt: pinned ? asDate(uploadOf(releases[pinned])) : undefined,
    previousStableVersion,
    hasInstallScript: undefined, // not knowable from PyPI metadata
  };
}

function asDate(t) {
  return t === undefined ? undefined : new Date(t);
}

/**
 * Run all heuristic checks against a set of requested packages.
 *
 * Findings mirror the IoC finding shape loosely: { rule, severity, name,
 * spec, message, suggestion }. Severity policy:
 *   - nonexistent package        → high   (likely LLM hallucination / slopsquat bait)
 *   - typosquat lookalike        → high
 *   - version inside cooldown    → high   (block, suggest previous stable)
 *   - package < 7 days old       → high
 *   - has install scripts        → info   (context, never blocks alone)
 *
 * @param {Array<{name: string, spec: string|null}>} packages
 * @param {'npm'|'pypi'} ecosystem
 * @param {{ offline?: boolean, cooldownHours?: number, fetchFn?: typeof fetch }} [options]
 * @returns {Promise<{ findings: Array, checked: number, networkSkipped: boolean }>}
 */
export async function runHeuristics(packages, ecosystem, options = {}) {
  const cooldownHours = options.cooldownHours ?? DEFAULT_COOLDOWN_HOURS;
  const findings = [];
  let networkSkipped = Boolean(options.offline);

  for (const pkg of packages) {
    const squat = await checkTyposquat(pkg.name, ecosystem);
    if (squat.suspicious) {
      findings.push({
        rule: 'typosquat-lookalike',
        severity: 'high',
        name: pkg.name,
        spec: pkg.spec,
        message: `"${pkg.name}" is ${squat.reason}. If an LLM suggested this name, it may be slopsquatted.`,
        suggestion: `Did you mean "${squat.lookalikeOf}"?`,
      });
    }

    if (options.offline) continue;

    const meta = await fetchRegistryMetadata(pkg.name, pkg.spec, ecosystem, {
      fetchFn: options.fetchFn ?? fetch,
      cooldownHours,
    });
    if (meta === null) {
      networkSkipped = true; // fail open, but tell the caller checks were incomplete
      continue;
    }

    if (!meta.exists) {
      findings.push({
        rule: 'nonexistent-package',
        severity: 'high',
        name: pkg.name,
        spec: pkg.spec,
        message: `"${pkg.name}" does not exist on the ${ecosystem} registry. If an AI assistant suggested it, this is a hallucinated package name — the exact pattern slopsquatting attacks exploit.`,
        suggestion: 'Do not retry with small spelling variations; find the real package name in the project docs.',
      });
      continue;
    }

    const now = Date.now();
    if (meta.createdAt && now - meta.createdAt.getTime() < NEW_PACKAGE_DAYS * 24 * 3600 * 1000) {
      findings.push({
        rule: 'brand-new-package',
        severity: 'high',
        name: pkg.name,
        spec: pkg.spec,
        message: `"${pkg.name}" was first published ${humanAge(now - meta.createdAt.getTime())} ago. Brand-new packages are the primary vehicle for slopsquatting and malware uploads.`,
        suggestion: 'Verify this is the package you intend before installing.',
      });
    }

    const relevantPublish = meta.versionPublishedAt ?? meta.latestPublishedAt;
    const targetVersion = meta.versionPublishedAt ? pkg.spec : meta.latestVersion;
    if (relevantPublish && now - relevantPublish.getTime() < cooldownHours * 3600 * 1000) {
      const isAlsoNew = findings.some((f) => f.rule === 'brand-new-package' && f.name === pkg.name);
      if (!isAlsoNew) {
        findings.push({
          rule: 'cooldown-violation',
          severity: 'high',
          name: pkg.name,
          spec: pkg.spec,
          message: `${pkg.name}@${targetVersion} was published ${humanAge(now - relevantPublish.getTime())} ago — inside the ${cooldownHours}h cooldown window. Most supply-chain attacks are caught within days of upload; waiting out the window avoids being patient zero.`,
          suggestion: meta.previousStableVersion
            ? `Install the previous stable version instead: ${pkg.name}@${meta.previousStableVersion}`
            : `Wait for the cooldown window to pass, or override the cooldown if you trust this release.`,
          previousStableVersion: meta.previousStableVersion,
        });
      }
    }

    if (meta.hasInstallScript) {
      findings.push({
        rule: 'install-scripts',
        severity: 'info',
        name: pkg.name,
        spec: pkg.spec,
        message: `${pkg.name} runs lifecycle install scripts (preinstall/install/postinstall) — the mechanism npm supply-chain malware uses to execute.`,
        suggestion: 'Informational; combined with other signals this raises risk.',
      });
    }
  }

  return { findings, checked: packages.length, networkSkipped };
}

function humanAge(ms) {
  const hours = ms / 3600000;
  if (hours < 1) return `${Math.max(1, Math.round(ms / 60000))} minutes`;
  if (hours < 48) return `${Math.round(hours)} hours`;
  return `${Math.round(hours / 24)} days`;
}
