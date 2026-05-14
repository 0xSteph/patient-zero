import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, writeFile, mkdir, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { loadIocs } from '../src/ioc-loader.js';

const MIN_VALID = {
  schema_version: '1.0',
  generated_at: '2026-01-01T00:00:00Z',
  coverage_window: { start: '2025-09-01', end: 'present' },
  attack_family_count: 0,
  indicator_count: 0,
  sources: [],
  attack_families: {},
  indicators: { package: [], file: [], process: [], github: [], network: [], mcp: [] },
  indexes: { packages_by_ecosystem_name: {} },
};

test('loadIocs: --offline returns bundled snapshot', async () => {
  const result = await loadIocs({ offline: true });
  assert.equal(result.source, 'bundled');
  assert.equal(result.iocs.schema_version, '1.0');
  assert.ok(typeof result.iocs.attack_family_count === 'number');
});

test('loadIocs: fetch path writes a fresh cache and returns source=fetched', async () => {
  const cacheDir = await mkdtemp(path.join(tmpdir(), 'p0-cache-'));
  try {
    const result = await loadIocs({
      fetchUrl: 'https://example.test/iocs.json',
      cacheDir,
      fetchFn: async () => ({ ok: true, json: async () => MIN_VALID }),
    });
    assert.equal(result.source, 'fetched');
    assert.deepEqual(result.iocs.coverage_window, MIN_VALID.coverage_window);

    // Cache file should now exist
    const { readFile } = await import('node:fs/promises');
    const cached = JSON.parse(await readFile(path.join(cacheDir, 'iocs.json'), 'utf8'));
    assert.equal(cached.schema_version, '1.0');
  } finally {
    await rm(cacheDir, { recursive: true, force: true });
  }
});

test('loadIocs: fresh cache (<1h) is used without fetching', async () => {
  const cacheDir = await mkdtemp(path.join(tmpdir(), 'p0-cache-'));
  try {
    await mkdir(cacheDir, { recursive: true });
    await writeFile(path.join(cacheDir, 'iocs.json'), JSON.stringify(MIN_VALID), 'utf8');
    let fetchCalled = false;
    const result = await loadIocs({
      cacheDir,
      fetchFn: async () => {
        fetchCalled = true;
        return { ok: true, json: async () => MIN_VALID };
      },
    });
    assert.equal(result.source, 'cache-fresh');
    assert.equal(fetchCalled, false, 'fresh cache should not trigger fetch');
  } finally {
    await rm(cacheDir, { recursive: true, force: true });
  }
});

test('loadIocs: fetch failure falls back to stale cache', async () => {
  const cacheDir = await mkdtemp(path.join(tmpdir(), 'p0-cache-'));
  try {
    await mkdir(cacheDir, { recursive: true });
    const cachePath = path.join(cacheDir, 'iocs.json');
    await writeFile(cachePath, JSON.stringify(MIN_VALID), 'utf8');
    // Make the cache "stale" by setting mtime > 1h ago
    const { utimes } = await import('node:fs/promises');
    const oldDate = new Date(Date.now() - 2 * 60 * 60 * 1000);
    await utimes(cachePath, oldDate, oldDate);

    const result = await loadIocs({
      cacheDir,
      fetchFn: async () => {
        throw new Error('network unreachable');
      },
    });
    assert.equal(result.source, 'cache-stale');
  } finally {
    await rm(cacheDir, { recursive: true, force: true });
  }
});

test('loadIocs: fetch failure with no cache falls back to bundled', async () => {
  const cacheDir = await mkdtemp(path.join(tmpdir(), 'p0-cache-'));
  try {
    const result = await loadIocs({
      cacheDir,
      fetchFn: async () => {
        throw new Error('network unreachable');
      },
    });
    assert.equal(result.source, 'bundled');
  } finally {
    await rm(cacheDir, { recursive: true, force: true });
  }
});

test('loadIocs: fetched doc with unsupported schema_version major triggers bundled fallback', async () => {
  const cacheDir = await mkdtemp(path.join(tmpdir(), 'p0-cache-'));
  try {
    const result = await loadIocs({
      fetchFn: async () => ({ ok: true, json: async () => ({ ...MIN_VALID, schema_version: '2.0' }) }),
      cacheDir,
    });
    // Loader is resilient: bad remote data should NOT crash the CLI; it falls back to bundled.
    assert.equal(result.source, 'bundled', `expected bundled fallback, got ${result.source}`);
    assert.equal(result.iocs.schema_version, '1.0');
  } finally {
    await rm(cacheDir, { recursive: true, force: true });
  }
});

test('loadIocs: PATIENT_ZERO_IOCS_PATH env override loads the specified file', async () => {
  const tmpFile = path.join(await mkdtemp(path.join(tmpdir(), 'p0-')), 'iocs.json');
  await writeFile(tmpFile, JSON.stringify(MIN_VALID), 'utf8');
  const prev = process.env.PATIENT_ZERO_IOCS_PATH;
  process.env.PATIENT_ZERO_IOCS_PATH = tmpFile;
  try {
    const result = await loadIocs({});
    assert.equal(result.source, 'env-override');
    assert.equal(result.iocs.schema_version, '1.0');
  } finally {
    if (prev === undefined) delete process.env.PATIENT_ZERO_IOCS_PATH;
    else process.env.PATIENT_ZERO_IOCS_PATH = prev;
  }
});
