import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFile, mkdtemp, writeFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { detectPackageManager } from '../src/scanners/install-tree.js';
import { matchTreeAgainstIocs, runInterceptor } from '../src/install-interceptor.js';

const HERE = path.dirname(fileURLToPath(import.meta.url));

async function loadFixtureIocs() {
  return JSON.parse(await readFile(path.join(HERE, 'fixtures/iocs-test.json'), 'utf8'));
}

// ---------- package manager detection ----------

test('detectPackageManager: defaults to npm with no lockfile', async () => {
  const dir = await mkdtemp(path.join(tmpdir(), 'p0-pm-'));
  try {
    assert.equal(detectPackageManager(dir), 'npm');
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('detectPackageManager: detects pnpm from pnpm-lock.yaml', async () => {
  const dir = await mkdtemp(path.join(tmpdir(), 'p0-pm-'));
  try {
    await writeFile(path.join(dir, 'pnpm-lock.yaml'), '', 'utf8');
    assert.equal(detectPackageManager(dir), 'pnpm');
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('detectPackageManager: detects yarn from yarn.lock', async () => {
  const dir = await mkdtemp(path.join(tmpdir(), 'p0-pm-'));
  try {
    await writeFile(path.join(dir, 'yarn.lock'), '', 'utf8');
    assert.equal(detectPackageManager(dir), 'yarn');
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('detectPackageManager: explicit override wins over lockfile detection', async () => {
  const dir = await mkdtemp(path.join(tmpdir(), 'p0-pm-'));
  try {
    await writeFile(path.join(dir, 'pnpm-lock.yaml'), '', 'utf8');
    assert.equal(detectPackageManager(dir, { pm: 'npm' }), 'npm');
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

// ---------- matchTreeAgainstIocs ----------

test('matchTreeAgainstIocs: matches packages in resolved tree against IoC database', async () => {
  const iocs = await loadFixtureIocs();
  const resolved = [
    { name: 'fake-malicious-pkg', version: '1.0.0', ecosystem: 'npm' },
    { name: 'lodash', version: '4.17.21', ecosystem: 'npm' },
    { name: 'chalk', version: '4.0.0', ecosystem: 'npm' },
  ];
  const findings = matchTreeAgainstIocs(resolved, iocs);
  assert.equal(findings.length, 2, 'expected 2 findings (fake-malicious-pkg + chalk@4.0.0)');
  const names = findings.map((f) => f.artifact.name).sort();
  assert.deepEqual(names, ['chalk', 'fake-malicious-pkg']);
});

test('matchTreeAgainstIocs: chalk@5.0.0 does NOT match IoC for chalk@4.0.0 (no false positive)', async () => {
  const iocs = await loadFixtureIocs();
  const resolved = [{ name: 'chalk', version: '5.0.0', ecosystem: 'npm' }];
  const findings = matchTreeAgainstIocs(resolved, iocs);
  assert.equal(findings.length, 0);
});

test('matchTreeAgainstIocs: clean install (nothing matches) returns empty', async () => {
  const iocs = await loadFixtureIocs();
  const resolved = [
    { name: 'lodash', version: '4.17.21', ecosystem: 'npm' },
    { name: 'express', version: '4.17.1', ecosystem: 'npm' },
  ];
  const findings = matchTreeAgainstIocs(resolved, iocs);
  assert.equal(findings.length, 0);
});

// ---------- runInterceptor (end-to-end with mocked resolveFn) ----------

test('runInterceptor: clean install passes through to real install', async () => {
  const iocs = await loadFixtureIocs();
  let passedThroughArgs = null;
  const result = await runInterceptor({
    pkgs: ['lodash'],
    iocs,
    pm: 'npm',
    resolveFn: async () => [{ name: 'lodash', version: '4.17.21', ecosystem: 'npm' }],
    passThroughFn: async (pm, pkgs) => {
      passedThroughArgs = { pm, pkgs };
      return { code: 0 };
    },
  });
  assert.equal(result.passedThrough, true);
  assert.equal(result.findings.length, 0);
  assert.equal(result.exitCode, 0);
  assert.deepEqual(passedThroughArgs, { pm: 'npm', pkgs: ['lodash'] });
});

test('runInterceptor: dirty install is blocked, postinstall never runs', async () => {
  const iocs = await loadFixtureIocs();
  let passedThroughCalled = false;
  const result = await runInterceptor({
    pkgs: ['fake-malicious-pkg'],
    iocs,
    pm: 'npm',
    resolveFn: async () => [
      { name: 'fake-malicious-pkg', version: '1.0.0', ecosystem: 'npm' },
      { name: 'some-transitive', version: '2.0.0', ecosystem: 'npm' },
    ],
    passThroughFn: async () => {
      passedThroughCalled = true;
      return { code: 0 };
    },
  });
  assert.equal(result.passedThrough, false, 'must NOT pass through when findings exist');
  assert.equal(passedThroughCalled, false, 'postinstall script must NOT have been allowed to run');
  assert.equal(result.findings.length, 1);
  assert.equal(result.findings[0].artifact.name, 'fake-malicious-pkg');
  assert.equal(result.exitCode, 1);
});

test('runInterceptor: transitive dependency match blocks the install', async () => {
  const iocs = await loadFixtureIocs();
  // User asks to install something benign, but the resolved tree pulls in chalk@4.0.0 transitively.
  const result = await runInterceptor({
    pkgs: ['some-app'],
    iocs,
    pm: 'npm',
    resolveFn: async () => [
      { name: 'some-app', version: '1.0.0', ecosystem: 'npm' },
      { name: 'chalk', version: '4.0.0', ecosystem: 'npm' }, // transitive
      { name: 'lodash', version: '4.17.21', ecosystem: 'npm' },
    ],
    passThroughFn: async () => ({ code: 0 }),
  });
  assert.equal(result.findings.length, 1);
  assert.equal(result.findings[0].artifact.name, 'chalk');
  assert.equal(result.passedThrough, false, 'transitive hit must block');
});

test('runInterceptor: resolve failure returns exit code 2 without passing through', async () => {
  const iocs = await loadFixtureIocs();
  let passedThroughCalled = false;
  const result = await runInterceptor({
    pkgs: ['some-pkg'],
    iocs,
    pm: 'npm',
    resolveFn: async () => { throw new Error('npm dry-run failed: network error'); },
    passThroughFn: async () => { passedThroughCalled = true; return { code: 0 }; },
  });
  assert.equal(result.exitCode, 2);
  assert.equal(result.passedThrough, false);
  assert.equal(passedThroughCalled, false);
  assert.match(result.error, /dry-run failed/);
});

test('runInterceptor: onProgress callback receives expected events in order', async () => {
  const iocs = await loadFixtureIocs();
  const events = [];
  await runInterceptor({
    pkgs: ['lodash'],
    iocs,
    pm: 'npm',
    resolveFn: async () => [{ name: 'lodash', version: '4.17.21', ecosystem: 'npm' }],
    passThroughFn: async () => ({ code: 0 }),
    onProgress: (event) => events.push(event),
  });
  assert.deepEqual(events, ['detect', 'resolved', 'scanned', 'passthrough']);
});
