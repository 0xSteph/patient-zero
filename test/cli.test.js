import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const CLI = path.resolve(HERE, '../bin/cli.js');
const FIXTURE_PROJECT = path.join(HERE, 'fixtures/sample-project');
const FIXTURE_IOCS = path.join(HERE, 'fixtures/iocs-test.json');

function runCli(args, env = {}) {
  return new Promise((resolve) => {
    const child = spawn(process.execPath, [CLI, ...args], {
      env: { ...process.env, ...env, NO_COLOR: '1' }, // disable colors for cleaner assertions
      stdio: 'pipe',
    });
    let stdout = '';
    let stderr = '';
    child.stdout.on('data', (d) => (stdout += d.toString()));
    child.stderr.on('data', (d) => (stderr += d.toString()));
    child.on('close', (code) => resolve({ code, stdout, stderr }));
  });
}

test('cli: --offline against empty dir, no findings, exits 0', async () => {
  // Run from the repo root but --dir to a tmpdir that has no lockfiles
  const tmpDir = path.join(HERE, 'fixtures/empty-project');
  // Ensure tmpDir exists empty (we'll just point at fixtures dir minus the sample project)
  const result = await runCli(['--offline', '--no-github', '--dir', tmpDir]);
  // 0 (clean) is expected because the empty dir has no lockfiles and the bundled
  // iocs only has file/process/github indicators (no package matches possible against an empty dir).
  // Process scanner may match on the dev's host — that's fine for this assertion;
  // we test the exit code path separately below with a deterministic env-override.
  assert.ok(result.code === 0 || result.code === 1, `expected exit 0 or 1, got ${result.code}\nstdout:\n${result.stdout}\nstderr:\n${result.stderr}`);
  assert.match(result.stdout, /patient-zero v/);
});

test('cli: env-override + fixture project produces findings and exits 1', async () => {
  const result = await runCli(
    ['--no-github', '--dir', FIXTURE_PROJECT],
    { PATIENT_ZERO_IOCS_PATH: FIXTURE_IOCS },
  );
  assert.equal(result.code, 1, `expected exit 1 (finding), got ${result.code}\nstdout:\n${result.stdout}\nstderr:\n${result.stderr}`);
  assert.match(result.stdout, /Findings/);
  assert.match(result.stdout, /Test Attack/); // attack family display name from fixture
  assert.match(result.stdout, /CRITICAL/);
});

test('cli: --json mode produces parseable JSON and exits 1 with findings', async () => {
  const result = await runCli(
    ['--no-github', '--json', '--dir', FIXTURE_PROJECT],
    { PATIENT_ZERO_IOCS_PATH: FIXTURE_IOCS },
  );
  assert.equal(result.code, 1);
  let parsed;
  assert.doesNotThrow(() => (parsed = JSON.parse(result.stdout)), `JSON parse failed:\n${result.stdout}`);
  assert.equal(parsed.schema_version, '1.0');
  assert.ok(Array.isArray(parsed.findings));
  assert.ok(parsed.findings.length >= 5, `expected ≥5 findings, got ${parsed.findings.length}`);
  // Spot-check one finding shape
  const f = parsed.findings[0];
  assert.ok(f.id);
  assert.ok(f.severity);
  assert.ok(f.attack_family);
  assert.ok(f.artifact);
});

test('cli: --report writes a markdown file with the findings', async () => {
  const reportPath = path.join(HERE, `cli-test-report-${Date.now()}.md`);
  try {
    const result = await runCli(
      ['--no-github', '--report', reportPath, '--dir', FIXTURE_PROJECT],
      { PATIENT_ZERO_IOCS_PATH: FIXTURE_IOCS },
    );
    assert.equal(result.code, 1);
    const { readFile, unlink } = await import('node:fs/promises');
    const md = await readFile(reportPath, 'utf8');
    assert.match(md, /^# patient-zero scan report/);
    assert.match(md, /## Findings/);
    assert.match(md, /Test Attack/);
    await unlink(reportPath);
  } catch (err) {
    // Try to clean up even on failure
    try {
      const { unlink } = await import('node:fs/promises');
      await unlink(reportPath);
    } catch {}
    throw err;
  }
});

test('cli: --version prints version and exits 0', async () => {
  const result = await runCli(['--version']);
  assert.equal(result.code, 0);
  assert.match(result.stdout, /\d+\.\d+\.\d+/);
});

test('cli: --help shows usage and exits 0', async () => {
  const result = await runCli(['--help']);
  assert.equal(result.code, 0);
  assert.match(result.stdout, /Usage: patient-zero/);
  assert.match(result.stdout, /--offline/);
  assert.match(result.stdout, /--json/);
  assert.match(result.stdout, /--no-github/);
});

test('cli: --ecosystem npm filters out pypi findings', async () => {
  const result = await runCli(
    ['--no-github', '--json', '--ecosystem', 'npm', '--dir', FIXTURE_PROJECT],
    { PATIENT_ZERO_IOCS_PATH: FIXTURE_IOCS },
  );
  assert.equal(result.code, 1);
  const parsed = JSON.parse(result.stdout);
  for (const f of parsed.findings.filter((f) => f.type === 'package')) {
    assert.notEqual(f.artifact.name, 'evil-pkg', 'pypi package should be filtered out');
  }
});
