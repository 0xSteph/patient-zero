import { readdir } from 'node:fs/promises';
import path from 'node:path';

const DEFAULT_IGNORE = new Set([
  'node_modules',
  '.git',
  '.svn',
  '.hg',
  'vendor',
  '__pycache__',
  '.venv',
  'venv',
  'env',
  '.tox',
  'target',
  'dist',
  'build',
  '.next',
  '.nuxt',
  '.turbo',
]);

/**
 * Walk a directory tree up to `depth` levels deep, yielding files whose
 * basename matches one of `targets`. Skips common ignored directories.
 *
 * @param {string} root
 * @param {{ targets: string[], depth?: number, ignore?: Set<string> }} options
 * @returns {Promise<string[]>} absolute paths
 */
export async function findFiles(root, { targets, depth = 5, ignore = DEFAULT_IGNORE } = {}) {
  const targetSet = new Set(targets);
  const found = [];

  async function walk(dir, level) {
    if (level > depth) return;
    let entries;
    try {
      entries = await readdir(dir, { withFileTypes: true });
    } catch {
      return;
    }
    for (const entry of entries) {
      if (entry.isSymbolicLink()) continue;
      const full = path.join(dir, entry.name);
      if (entry.isDirectory()) {
        if (ignore.has(entry.name)) continue;
        if (entry.name.startsWith('.') && entry.name !== '.config') continue;
        await walk(full, level + 1);
      } else if (entry.isFile() && targetSet.has(entry.name)) {
        found.push(full);
      }
    }
  }

  await walk(path.resolve(root), 0);
  return found;
}
