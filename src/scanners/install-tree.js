import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { existsSync } from 'node:fs';
import { copyFile, mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { parsePackageLock, parsePnpmLock } from './lockfile-parsers.js';

const execFileAsync = promisify(execFile);

/**
 * Detect which package manager to use for an install command.
 * Priority: explicit override > lockfile-in-cwd > "npm" default.
 *
 * @param {string} cwd
 * @param {{ pm?: 'npm'|'pnpm'|'yarn' }} options
 * @returns {'npm'|'pnpm'|'yarn'}
 */
export function detectPackageManager(cwd, options = {}) {
  if (options.pm) return options.pm;
  if (existsSync(path.join(cwd, 'pnpm-lock.yaml'))) return 'pnpm';
  if (existsSync(path.join(cwd, 'yarn.lock'))) return 'yarn';
  return 'npm';
}

/**
 * Resolve the dependency tree for a proposed install without running scripts.
 *
 * Strategy: copy the project's manifest (package.json + lockfile) to a temp
 * directory, run a real `--package-lock-only --ignore-scripts` install there,
 * then parse the resulting lockfile. This gives the full transitive tree the
 * proposed install would produce, without touching the user's node_modules
 * and without ever executing postinstall scripts.
 *
 * @param {{ pm: 'npm'|'pnpm'|'yarn', pkgs: string[], cwd: string, execFn?: typeof execFileAsync }} args
 * @returns {Promise<Array<{name: string, version: string, ecosystem: 'npm'}>>}
 */
export async function resolveInstallTree({ pm, pkgs, cwd, execFn = execFileAsync }) {
  if (pm === 'npm') return resolveViaTempDir('npm', pkgs, cwd, execFn);
  if (pm === 'pnpm') return resolveViaTempDir('pnpm', pkgs, cwd, execFn);
  if (pm === 'yarn') {
    throw new Error(
      'yarn install interception is not supported in v0.2; run `yarn add ...` then `npx patient-zero` to scan the result',
    );
  }
  throw new Error(`unsupported package manager: ${pm}`);
}

async function resolveViaTempDir(pm, pkgs, cwd, execFn) {
  const dir = await mkdtemp(path.join(tmpdir(), 'p0-resolve-'));
  try {
    await stageManifest(dir, cwd, pm);

    if (pm === 'npm') {
      await execFn(
        'npm',
        ['install', '--package-lock-only', '--ignore-scripts', ...pkgs],
        { cwd: dir, maxBuffer: 32 * 1024 * 1024 },
      );
      return parsePackageLock(path.join(dir, 'package-lock.json'));
    }

    if (pm === 'pnpm') {
      await execFn(
        'pnpm',
        ['add', '--lockfile-only', '--ignore-scripts', '--reporter=silent', ...pkgs],
        { cwd: dir, maxBuffer: 32 * 1024 * 1024 },
      );
      return parsePnpmLock(path.join(dir, 'pnpm-lock.yaml'));
    }

    throw new Error(`unsupported package manager in resolveViaTempDir: ${pm}`);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
}

/**
 * Copy package.json + lockfile from `cwd` to `dest` so the temp resolve
 * honors existing version constraints. If `cwd` has no manifest, write a
 * minimal one.
 */
async function stageManifest(dest, cwd, pm) {
  const pkgJsonSrc = path.join(cwd, 'package.json');
  if (existsSync(pkgJsonSrc)) {
    await copyFile(pkgJsonSrc, path.join(dest, 'package.json'));
  } else {
    await writeFile(
      path.join(dest, 'package.json'),
      JSON.stringify({ name: 'p0-resolve', version: '0.0.0' }) + '\n',
      'utf8',
    );
  }

  if (pm === 'npm') {
    const lockSrc = path.join(cwd, 'package-lock.json');
    if (existsSync(lockSrc)) await copyFile(lockSrc, path.join(dest, 'package-lock.json'));
  } else if (pm === 'pnpm') {
    const lockSrc = path.join(cwd, 'pnpm-lock.yaml');
    if (existsSync(lockSrc)) await copyFile(lockSrc, path.join(dest, 'pnpm-lock.yaml'));
    const wsSrc = path.join(cwd, 'pnpm-workspace.yaml');
    if (existsSync(wsSrc)) await copyFile(wsSrc, path.join(dest, 'pnpm-workspace.yaml'));
  }
}
