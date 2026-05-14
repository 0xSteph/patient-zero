import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { scan } from '../src/scanners/lockfiles.js';
import {
  parsePackageLock,
  parsePnpmLock,
  parseYarnLock,
  parseRequirementsTxt,
  parsePoetryLock,
} from '../src/scanners/lockfile-parsers.js';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const FIXTURE_PROJECT = path.join(HERE, 'fixtures/sample-project');
const FIXTURE_IOCS = path.join(HERE, 'fixtures/iocs-test.json');

async function loadIocs() {
  return JSON.parse(await readFile(FIXTURE_IOCS, 'utf8'));
}

test('parsePackageLock extracts npm packages from v3 lockfile', async () => {
  const entries = await parsePackageLock(path.join(FIXTURE_PROJECT, 'package-lock.json'));
  const names = entries.map((e) => e.name).sort();
  assert.deepEqual(names, ['chalk', 'express', 'fake-malicious-pkg']);
  const fake = entries.find((e) => e.name === 'fake-malicious-pkg');
  assert.equal(fake.version, '1.0.0');
  assert.equal(fake.ecosystem, 'npm');
});

test('parseYarnLock extracts npm packages including scoped', async () => {
  const entries = await parseYarnLock(path.join(FIXTURE_PROJECT, 'yarn.lock'));
  const names = entries.map((e) => e.name).sort();
  assert.deepEqual(names, ['@scoped/pkg', 'ansi-styles', 'chalk']);
  const chalk = entries.find((e) => e.name === 'chalk');
  assert.equal(chalk.version, '4.0.0');
});

test('parsePnpmLock extracts npm packages including scoped (v9 format)', async () => {
  const entries = await parsePnpmLock(path.join(FIXTURE_PROJECT, 'pnpm-lock.yaml'));
  const names = entries.map((e) => e.name).sort();
  assert.ok(names.includes('fake-malicious-pkg'), `expected fake-malicious-pkg in ${names.join(',')}`);
  assert.ok(names.includes('express'));
  assert.ok(names.includes('@scoped/pkg'));
  const fake = entries.find((e) => e.name === 'fake-malicious-pkg');
  assert.equal(fake.version, '1.0.0');
});

test('parseRequirementsTxt extracts only exact-pinned packages', async () => {
  const entries = await parseRequirementsTxt(path.join(FIXTURE_PROJECT, 'requirements.txt'));
  const names = entries.map((e) => e.name).sort();
  // django is range-pinned (>=4.0.0); should be skipped
  assert.deepEqual(names, ['evil-pkg', 'flask', 'requests']);
  const evil = entries.find((e) => e.name === 'evil-pkg');
  assert.equal(evil.version, '2.3.4');
  assert.equal(evil.ecosystem, 'pypi');
});

test('parsePoetryLock extracts pypi packages', async () => {
  const entries = await parsePoetryLock(path.join(FIXTURE_PROJECT, 'poetry.lock'));
  const names = entries.map((e) => e.name).sort();
  assert.deepEqual(names, ['evil-pkg', 'requests']);
});

test('scan: finds all 5 expected matches across 5 lockfile types', async () => {
  const iocs = await loadIocs();
  const result = await scan(iocs, { root: FIXTURE_PROJECT });

  assert.equal(result.errors.length, 0, `unexpected errors: ${result.errors.join('; ')}`);
  assert.equal(result.scanned.lockfiles_found, 5, 'should find all 5 fixture lockfiles');

  // Expected matches:
  //   package-lock.json: fake-malicious-pkg@1.0.0       (chalk@5.0.0 should NOT match)
  //   yarn.lock:         chalk@4.0.0
  //   pnpm-lock.yaml:    fake-malicious-pkg@1.0.0
  //   requirements.txt:  evil-pkg==2.3.4
  //   poetry.lock:       evil-pkg 2.3.4
  // Total: 5 findings
  assert.equal(result.findings.length, 5, `expected 5 findings, got ${result.findings.length}`);

  const byLockfile = {};
  for (const f of result.findings) {
    byLockfile[path.basename(f.artifact.lockfile)] = f;
  }
  assert.equal(byLockfile['package-lock.json'].artifact.name, 'fake-malicious-pkg');
  assert.equal(byLockfile['yarn.lock'].artifact.name, 'chalk');
  assert.equal(byLockfile['yarn.lock'].artifact.version, '4.0.0');
  assert.equal(byLockfile['pnpm-lock.yaml'].artifact.name, 'fake-malicious-pkg');
  assert.equal(byLockfile['requirements.txt'].artifact.name, 'evil-pkg');
  assert.equal(byLockfile['poetry.lock'].artifact.name, 'evil-pkg');
});

test('scan: chalk@5.0.0 in package-lock does NOT match IoC for chalk@4.0.0 (no false positive)', async () => {
  const iocs = await loadIocs();
  const result = await scan(iocs, { root: FIXTURE_PROJECT });
  const chalkMatches = result.findings.filter((f) => f.artifact.name === 'chalk');
  // Only the yarn.lock chalk@4.0.0 should match. Not the package-lock chalk@5.0.0.
  assert.equal(chalkMatches.length, 1, `expected exactly 1 chalk match (yarn.lock @ 4.0.0), got ${chalkMatches.length}`);
  assert.equal(chalkMatches[0].artifact.version, '4.0.0');
});

test('scan: --ecosystem npm filter excludes pypi packages', async () => {
  const iocs = await loadIocs();
  const result = await scan(iocs, { root: FIXTURE_PROJECT, ecosystem: 'npm' });
  // npm-only: fake-malicious-pkg x2 + chalk x1 = 3
  assert.equal(result.findings.length, 3, `expected 3 npm findings, got ${result.findings.length}`);
  assert.ok(result.findings.every((f) => f.indicator.ecosystem === 'npm'));
});

test('scan: --ecosystem pypi filter excludes npm packages', async () => {
  const iocs = await loadIocs();
  const result = await scan(iocs, { root: FIXTURE_PROJECT, ecosystem: 'pypi' });
  // pypi-only: evil-pkg in requirements.txt + evil-pkg in poetry.lock = 2
  assert.equal(result.findings.length, 2, `expected 2 pypi findings, got ${result.findings.length}`);
  assert.ok(result.findings.every((f) => f.indicator.ecosystem === 'pypi'));
});

test('scan: depth=0 finds nothing outside the root', async () => {
  const iocs = await loadIocs();
  // Run from FIXTURE_PROJECT's parent with depth=0 — should find nothing
  // because lockfiles live one level down inside sample-project/
  const result = await scan(iocs, { root: path.dirname(FIXTURE_PROJECT), depth: 0 });
  assert.equal(result.scanned.lockfiles_found, 0, 'depth=0 should not descend into subdirs');
});

test('scan: scanner ignores node_modules and other ignored dirs', async () => {
  const iocs = await loadIocs();
  // Place fixture under our actual repo root; we should NOT pick up patient-zero's own
  // node_modules during the test (which has package-lock.json deep inside).
  const repoRoot = path.resolve(HERE, '..');
  const result = await scan(iocs, { root: repoRoot, depth: 5 });
  // Our root has the fixture project's lockfiles plus possibly our own package-lock.json if it exists.
  // We should NOT find any node_modules/* lockfiles.
  for (const f of result.findings.concat([])) {
    assert.ok(!f.artifact.lockfile.includes('node_modules'), `should ignore node_modules, got ${f.artifact.lockfile}`);
  }
});
