import { readFile } from 'node:fs/promises';
import { parse as parseYaml } from 'yaml';
import { parse as parseToml } from 'smol-toml';

/**
 * Each parser reads a lockfile and returns an array of { name, version, ecosystem }.
 * Names are returned as-is (case preserved); the scanner lowercases for index lookup.
 */

export async function parsePackageLock(filePath) {
  const raw = await readFile(filePath, 'utf8');
  const doc = JSON.parse(raw);
  const out = [];

  // v7+ shape: `packages` map keyed by path
  if (doc.packages && typeof doc.packages === 'object') {
    for (const [key, entry] of Object.entries(doc.packages)) {
      if (key === '' || !entry?.version) continue;
      const name = entry.name ?? extractNameFromNodeModulesPath(key);
      if (!name) continue;
      out.push({ name, version: entry.version, ecosystem: 'npm' });
    }
  }

  // v5/v6 shape: `dependencies` recursive tree
  if (doc.dependencies && typeof doc.dependencies === 'object' && out.length === 0) {
    walkV5Tree(doc.dependencies, out);
  }

  return dedupe(out);
}

function extractNameFromNodeModulesPath(p) {
  if (!p.startsWith('node_modules/')) return null;
  const rest = p.slice('node_modules/'.length);
  if (rest.startsWith('@')) {
    const slash2 = rest.indexOf('/', rest.indexOf('/') + 1);
    return slash2 > 0 ? rest.slice(0, slash2).split('/node_modules/')[0] : rest;
  }
  const slash = rest.indexOf('/');
  return slash > 0 ? rest.slice(0, slash).split('/node_modules/')[0] : rest;
}

function walkV5Tree(deps, out) {
  for (const [name, entry] of Object.entries(deps)) {
    if (entry?.version) out.push({ name, version: entry.version, ecosystem: 'npm' });
    if (entry?.dependencies) walkV5Tree(entry.dependencies, out);
  }
}

export async function parsePnpmLock(filePath) {
  const raw = await readFile(filePath, 'utf8');
  const doc = parseYaml(raw);
  const out = [];
  const packages = doc?.packages;
  if (!packages || typeof packages !== 'object') return out;

  for (const key of Object.keys(packages)) {
    // pnpm v9: "<name>@<version>(<peer>...)"
    // pnpm v6/v7: "/<name>/<version>(<peer>...)" or "/<scope>/<name>/<version>"
    let nameVersion = key;
    if (nameVersion.startsWith('/')) nameVersion = nameVersion.slice(1);
    const peerIdx = nameVersion.indexOf('(');
    if (peerIdx > 0) nameVersion = nameVersion.slice(0, peerIdx);

    // Now nameVersion is like "name@version" OR "name/version" (older pnpm)
    let name, version;
    if (nameVersion.includes('@') && !nameVersion.endsWith('/')) {
      // New format: name@version, but watch for scoped packages
      const lastAt = nameVersion.lastIndexOf('@');
      if (lastAt > 0) {
        name = nameVersion.slice(0, lastAt);
        version = nameVersion.slice(lastAt + 1);
      }
    }
    if (!name && nameVersion.includes('/')) {
      // Older format: name/version
      const lastSlash = nameVersion.lastIndexOf('/');
      name = nameVersion.slice(0, lastSlash);
      version = nameVersion.slice(lastSlash + 1);
    }

    if (name && version) {
      out.push({ name, version, ecosystem: 'npm' });
    }
  }
  return dedupe(out);
}

export async function parseYarnLock(filePath) {
  const raw = await readFile(filePath, 'utf8');
  const out = [];
  const blocks = raw.split(/\n\n+/);

  for (const block of blocks) {
    const lines = block.split('\n');
    const headerLine = lines[0]?.trim();
    if (!headerLine || headerLine.startsWith('#')) continue;
    if (!headerLine.endsWith(':')) continue;

    const versionLine = lines.find((l) => /^\s*version\s+/.test(l));
    if (!versionLine) continue;
    const m = versionLine.match(/version\s+"?([^"\s]+)"?/);
    if (!m) continue;
    const version = m[1];

    const specsStr = headerLine.slice(0, -1);
    const specs = specsStr.split(',').map((s) => s.trim().replace(/^"|"$/g, ''));
    const names = new Set();
    for (const spec of specs) {
      const name = extractNameFromYarnSpec(spec);
      if (name) names.add(name);
    }
    for (const name of names) {
      out.push({ name, version, ecosystem: 'npm' });
    }
  }
  return dedupe(out);
}

function extractNameFromYarnSpec(spec) {
  // spec like: "react@^17.0.0" or "@scope/pkg@^1.0.0" or "react@npm:^17.0.0"
  // Find the @ that splits name from range. For scoped pkgs, name itself starts with @.
  const at = spec.lastIndexOf('@');
  if (at <= 0) return null;
  return spec.slice(0, at);
}

export async function parseRequirementsTxt(filePath) {
  const raw = await readFile(filePath, 'utf8');
  const out = [];
  for (const rawLine of raw.split('\n')) {
    const line = rawLine.split('#')[0].trim();
    if (!line) continue;
    if (line.startsWith('-')) continue; // skip options like -r, -e, etc.
    // Match `name==version` (exact pin only — we don't try to resolve ranges)
    const m = line.match(/^([A-Za-z0-9_.-]+)\s*==\s*([A-Za-z0-9_.+\-!]+)/);
    if (!m) continue;
    out.push({ name: m[1], version: m[2], ecosystem: 'pypi' });
  }
  return dedupe(out);
}

export async function parsePoetryLock(filePath) {
  const raw = await readFile(filePath, 'utf8');
  const doc = parseToml(raw);
  const out = [];
  const pkgs = Array.isArray(doc.package) ? doc.package : [];
  for (const pkg of pkgs) {
    if (pkg?.name && pkg?.version) {
      out.push({ name: String(pkg.name), version: String(pkg.version), ecosystem: 'pypi' });
    }
  }
  return dedupe(out);
}

function dedupe(entries) {
  const seen = new Set();
  return entries.filter((e) => {
    const key = `${e.ecosystem}:${e.name}@${e.version}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

export const LOCKFILE_PARSERS = {
  'package-lock.json': parsePackageLock,
  'pnpm-lock.yaml': parsePnpmLock,
  'yarn.lock': parseYarnLock,
  'requirements.txt': parseRequirementsTxt,
  'poetry.lock': parsePoetryLock,
};
