import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import path from 'node:path';
import { fetchManual } from '../aggregator/sources/manual.js';
import { merge } from '../aggregator/normalize.js';
import { validate } from '../aggregator/validate.js';
import { renderAttacks } from '../aggregator/render-attacks.js';

test('manual source reads data/manual-iocs.json and reports status=ok', async () => {
  const result = await fetchManual();
  assert.equal(result.name, 'manual');
  assert.equal(result.status, 'ok', `expected status=ok, got ${result.status} (${result.error ?? ''})`);
  assert.ok(Array.isArray(result.indicators), 'indicators must be an array');
  assert.ok(typeof result.attack_families === 'object', 'attack_families must be an object');
  assert.ok(result.indicators.length > 0, 'manual seed should have at least one indicator');
  assert.ok(Object.keys(result.attack_families).length >= 6, 'manual seed should have 6+ attack families');
});

test('merge produces the v1.0 grouped indicator shape', async () => {
  const sources = await Promise.all([fetchManual()]);
  const merged = merge(sources);

  assert.ok(merged.indicators.package, 'package bucket exists');
  assert.ok(merged.indicators.file, 'file bucket exists');
  assert.ok(merged.indicators.process, 'process bucket exists');
  assert.ok(merged.indicators.github, 'github bucket exists');
  assert.ok(merged.indicators.network, 'network bucket exists');
  assert.ok(merged.indicators.mcp, 'mcp bucket exists');

  assert.ok(merged.attack_family_count >= 6);
  assert.ok(merged.indicator_count >= 3, 'manual seed has at least 3 indicators');
  assert.equal(merged.coverage_window.end, 'present');
  assert.ok(merged.coverage_window.start, 'coverage window has a start date');
});

test('merge dedupes indicators by id', () => {
  const dup = {
    id: 'PZ-test-001',
    type: 'package',
    attack_family: 'test',
    severity: 'low',
    first_seen: '2026-01-01',
    last_updated: '2026-01-01',
    source: 'manual',
    description: 'test',
  };
  const src = (name) => ({
    name,
    fetched_at: new Date().toISOString(),
    status: 'ok',
    indicators: [dup],
    attack_families: { test: { display_name: 'test', first_observed: '2026-01-01', primary_external_source: { url: 'x' } } },
  });
  const merged = merge([src('a'), src('b')]);
  assert.equal(merged.indicators.package.length, 1, 'dup id should be deduped');
});

test('validate accepts a well-formed document', async () => {
  const sources = await Promise.all([fetchManual()]);
  const merged = merge(sources);
  const doc = {
    schema_version: '1.0',
    generated_at: new Date().toISOString(),
    coverage_window: merged.coverage_window,
    attack_family_count: merged.attack_family_count,
    indicator_count: merged.indicator_count,
    generator: { name: 'test', version: '0.0.0', run_id: 'test' },
    sources: merged.sources,
    attack_families: merged.attack_families,
    indicators: merged.indicators,
    indexes: merged.indexes,
  };
  const r = validate(doc);
  assert.equal(r.ok, true, `validate failed: ${r.ok ? '' : r.errors.join('; ')}`);
});

test('validate rejects critical indicator missing remediation', () => {
  const doc = {
    schema_version: '1.0',
    generated_at: new Date().toISOString(),
    coverage_window: { start: '2026-01-01', end: 'present' },
    attack_family_count: 1,
    indicator_count: 1,
    generator: {},
    sources: [],
    attack_families: {
      test: {
        display_name: 'test',
        first_observed: '2026-01-01',
        primary_external_source: { url: 'https://x' },
      },
    },
    indicators: {
      package: [],
      file: [
        {
          id: 'PZ-test-001',
          type: 'file',
          attack_family: 'test',
          severity: 'critical',
          first_seen: '2026-01-01',
          last_updated: '2026-01-01',
          source: 'manual',
          description: 'test',
          // remediation missing → must fail
        },
      ],
      process: [],
      github: [],
      network: [],
      mcp: [],
    },
    indexes: { packages_by_ecosystem_name: {} },
  };
  const r = validate(doc);
  assert.equal(r.ok, false);
  assert.ok(r.errors.some((e) => e.includes('remediation')), `expected remediation error, got: ${r.errors.join('; ')}`);
});

test('validate rejects attack_family missing primary_external_source', () => {
  const doc = {
    schema_version: '1.0',
    generated_at: new Date().toISOString(),
    coverage_window: { start: '2026-01-01', end: 'present' },
    attack_family_count: 1,
    indicator_count: 0,
    generator: {},
    sources: [],
    attack_families: {
      bad: { display_name: 'bad', first_observed: '2026-01-01' /* no primary_external_source */ },
    },
    indicators: { package: [], file: [], process: [], github: [], network: [], mcp: [] },
    indexes: { packages_by_ecosystem_name: {} },
  };
  const r = validate(doc);
  assert.equal(r.ok, false);
  assert.ok(r.errors.some((e) => e.includes('primary_external_source')));
});

test('renderAttacks produces a markdown table with one row per attack family', async () => {
  const sources = await Promise.all([fetchManual()]);
  const merged = merge(sources);
  const doc = {
    schema_version: '1.0',
    generated_at: '2026-05-14T18:00:00Z',
    coverage_window: merged.coverage_window,
    attack_family_count: merged.attack_family_count,
    indicator_count: merged.indicator_count,
    sources: merged.sources,
    attack_families: merged.attack_families,
    indicators: merged.indicators,
    indexes: merged.indexes,
  };
  const md = renderAttacks(doc);
  assert.match(md, /^# Tracked attacks/m);
  assert.match(md, /\| Attack family \|/);
  // Count data rows (lines starting with `| ` that aren't the header or separator)
  const tableLines = md.split('\n').filter((l) => /^\|/.test(l));
  // 1 header + 1 separator + N rows
  const dataRows = tableLines.length - 2;
  assert.equal(dataRows, merged.attack_family_count, `expected ${merged.attack_family_count} rows, got ${dataRows}`);
});

test('end-to-end: build.js --no-write succeeds', async () => {
  const { spawn } = await import('node:child_process');
  const child = spawn(process.execPath, ['aggregator/build.js', '--no-write'], {
    stdio: 'pipe',
  });
  let stdout = '';
  let stderr = '';
  child.stdout.on('data', (d) => (stdout += d.toString()));
  child.stderr.on('data', (d) => (stderr += d.toString()));
  const code = await new Promise((resolve) => child.on('close', resolve));
  assert.equal(code, 0, `aggregator exited with ${code}\nstdout:\n${stdout}\nstderr:\n${stderr}`);
  assert.match(stdout, /aggregator complete/);
  assert.match(stdout, /attack_families: \d+/);
});
