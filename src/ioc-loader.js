import { readFile, writeFile, mkdir, stat } from 'node:fs/promises';
import { homedir, platform } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const FETCH_URL = 'https://raw.githubusercontent.com/0xSteph/patient-zero/main/data/iocs.json';
const ONE_HOUR_MS = 60 * 60 * 1000;
const SUPPORTED_SCHEMA_MAJOR = 1;

const HERE = path.dirname(fileURLToPath(import.meta.url));
const BUNDLED_PATH = path.resolve(HERE, '../data/iocs.json');

/**
 * Load the IoC database. Strategy:
 *   1. If --offline, return the bundled snapshot.
 *   2. If a fresh (< 1h old) cached copy exists, return it.
 *   3. Otherwise fetch from raw.githubusercontent.com, cache, return.
 *   4. On fetch failure: fall back to stale cache, then to bundled snapshot.
 *
 * @param {{ offline?: boolean, fetchUrl?: string, cacheDir?: string, fetchFn?: typeof fetch }} [options]
 * @returns {Promise<{ iocs: Object, source: 'bundled'|'cache-fresh'|'cache-stale'|'fetched', ageMs: number }>}
 */
export async function loadIocs(options = {}) {
  const fetchUrl = options.fetchUrl ?? FETCH_URL;
  const cacheDir = options.cacheDir ?? defaultCacheDir();
  const cachePath = path.join(cacheDir, 'iocs.json');
  const fetchFn = options.fetchFn ?? fetch;

  // Test-only override
  const envPath = process.env.PATIENT_ZERO_IOCS_PATH;
  if (envPath) {
    const raw = await readFile(envPath, 'utf8');
    const data = JSON.parse(raw);
    verifySchema(data);
    return { iocs: data, source: 'env-override', ageMs: 0 };
  }

  if (options.offline) {
    const iocs = await loadBundled();
    return { iocs, source: 'bundled', ageMs: 0 };
  }

  // Try cache first
  const cacheStat = await safeStat(cachePath);
  if (cacheStat) {
    const ageMs = Date.now() - cacheStat.mtimeMs;
    if (ageMs < ONE_HOUR_MS) {
      try {
        const cached = JSON.parse(await readFile(cachePath, 'utf8'));
        verifySchema(cached);
        return { iocs: cached, source: 'cache-fresh', ageMs };
      } catch {
        // cache corrupt — fall through to fetch
      }
    }
  }

  // Try network
  try {
    const resp = await fetchFn(fetchUrl);
    if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
    const data = await resp.json();
    verifySchema(data);
    await mkdir(cacheDir, { recursive: true });
    await writeFile(cachePath, JSON.stringify(data), 'utf8');
    return { iocs: data, source: 'fetched', ageMs: 0 };
  } catch (fetchErr) {
    // Stale cache fallback
    if (cacheStat) {
      try {
        const cached = JSON.parse(await readFile(cachePath, 'utf8'));
        verifySchema(cached);
        return { iocs: cached, source: 'cache-stale', ageMs: Date.now() - cacheStat.mtimeMs };
      } catch {
        // fall through
      }
    }
    // Bundled fallback
    const iocs = await loadBundled();
    return { iocs, source: 'bundled', ageMs: 0 };
  }
}

async function loadBundled() {
  const raw = await readFile(BUNDLED_PATH, 'utf8');
  const data = JSON.parse(raw);
  verifySchema(data);
  return data;
}

function verifySchema(doc) {
  if (!doc?.schema_version) {
    throw new Error('iocs document missing schema_version');
  }
  const major = parseInt(String(doc.schema_version).split('.')[0], 10);
  if (major !== SUPPORTED_SCHEMA_MAJOR) {
    throw new Error(`unsupported schema_version: ${doc.schema_version} (this CLI supports v${SUPPORTED_SCHEMA_MAJOR}.x)`);
  }
}

function defaultCacheDir() {
  const home = homedir();
  if (platform() === 'win32') {
    return path.join(process.env.LOCALAPPDATA ?? path.join(home, 'AppData/Local'), 'patient-zero/cache');
  }
  if (platform() === 'darwin') {
    return path.join(home, 'Library/Caches/patient-zero');
  }
  return path.join(process.env.XDG_CACHE_HOME ?? path.join(home, '.cache'), 'patient-zero');
}

async function safeStat(p) {
  try {
    return await stat(p);
  } catch {
    return null;
  }
}
