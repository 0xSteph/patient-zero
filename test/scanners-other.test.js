import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFile, writeFile, mkdir, rm } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { tmpdir } from 'node:os';

import { scan as scanMcp } from '../src/scanners/mcp.js';
import { scan as scanLocalFiles } from '../src/scanners/local-files.js';
import { scan as scanProcesses } from '../src/scanners/processes.js';
import { scan as scanGithub } from '../src/scanners/github.js';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const FIXTURE_IOCS = path.join(HERE, 'fixtures/iocs-test-extended.json');
const FIXTURE_MCP_CLEAN = path.join(HERE, 'fixtures/mcp-configs/claude_clean.json');
const FIXTURE_MCP_BAD = path.join(HERE, 'fixtures/mcp-configs/claude_compromised.json');

async function loadIocs() {
  return JSON.parse(await readFile(FIXTURE_IOCS, 'utf8'));
}

// ---------- MCP scanner ----------

test('mcp scanner: clean config produces no findings', async () => {
  const iocs = await loadIocs();
  const result = await scanMcp(iocs, { configPaths: [FIXTURE_MCP_CLEAN] });
  assert.equal(result.errors.length, 0);
  assert.equal(result.findings.length, 0);
  assert.equal(result.scanned.configs_found, 1);
});

test('mcp scanner: compromised config flags the malicious server by name', async () => {
  const iocs = await loadIocs();
  const result = await scanMcp(iocs, { configPaths: [FIXTURE_MCP_BAD] });
  assert.equal(result.errors.length, 0);
  assert.ok(result.findings.length >= 1, `expected ≥1 finding, got ${result.findings.length}`);
  const f = result.findings[0];
  assert.equal(f.indicator.id, 'PZ-test-mcp-001');
  assert.match(f.artifact.config, /claude_compromised\.json$/);
  // Should cite at least one reason
  assert.ok(f.artifact.reasons.length >= 1);
});

test('mcp scanner: missing config file is silently skipped (no error)', async () => {
  const iocs = await loadIocs();
  const result = await scanMcp(iocs, { configPaths: ['/nonexistent/path/foo.json'] });
  assert.equal(result.errors.length, 0);
  assert.equal(result.findings.length, 0);
  assert.equal(result.scanned.configs_found, 0);
});

// ---------- Local file scanner ----------

// In production, file-indicator path_patterns target macOS LaunchAgents and Linux
// systemd units — neither exists on Windows. The path-regex mechanism is platform-
// agnostic in code, but the cross-platform quirks of compiling a Windows absolute
// path into a POSIX-style regex aren't worth fighting for a feature Windows users
// never trigger. Tested on Linux + macOS where it actually ships.
test('local-files scanner: finds a path matching an IoC regex', { skip: process.platform === 'win32' }, async () => {
  // Build a temp dir, drop a fake gh-token-monitor plist in it, point a forged IoC at it
  const dir = await mkdir(path.join(tmpdir(), `p0-test-${Date.now()}`), { recursive: true });
  try {
    const malPath = path.join(dir, 'com.gh-token-monitor.thing.plist');
    await writeFile(malPath, '<plist></plist>');

    const iocs = JSON.parse(await readFile(FIXTURE_IOCS, 'utf8'));
    // IoC schema documents path_patterns as using forward slashes (regex format).
    // Normalize the tmpdir separator so the test is platform-portable.
    const dirFwd = dir.replace(/\\/g, '/');
    iocs.indicators.file[0].path_patterns[0] = `${dirFwd}/com\\.gh-token-monitor.*\\.plist`;

    const result = await scanLocalFiles(iocs);
    assert.equal(result.errors.length, 0);
    // The scanner normalizes path separators internally; the reported artifact path
    // is platform-native (the value Node hands back from readdir + path.join).
    const expectedPath = malPath;
    assert.equal(result.findings.length, 1, `expected 1 finding, got ${result.findings.length}`);
    assert.equal(result.findings[0].artifact.path, expectedPath);
    assert.equal(result.findings[0].indicator.attack_family, 'shai-hulud-test');
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('local-files scanner: nonexistent directory in path_patterns is silently skipped', async () => {
  const iocs = JSON.parse(await readFile(FIXTURE_IOCS, 'utf8'));
  iocs.indicators.file[0].path_patterns[0] = '/nonexistent/dir/foo.*\\.plist';
  const result = await scanLocalFiles(iocs);
  assert.equal(result.errors.length, 0);
  assert.equal(result.findings.length, 0);
});

// ---------- Process scanner ----------

test('processes scanner: matches a process from the injected list', async () => {
  const iocs = await loadIocs();
  const result = await scanProcesses(iocs, {
    processList: async () => ['gh-token-monitor', 'node', 'zsh', 'systemd'],
  });
  assert.equal(result.errors.length, 0);
  assert.equal(result.findings.length, 1);
  assert.equal(result.findings[0].artifact.process, 'gh-token-monitor');
  assert.equal(result.findings[0].indicator.id, 'PZ-test-proc-001');
});

test('processes scanner: no match when target process is absent', async () => {
  const iocs = await loadIocs();
  const result = await scanProcesses(iocs, {
    processList: async () => ['node', 'zsh', 'systemd', 'firefox'],
  });
  assert.equal(result.findings.length, 0);
  assert.equal(result.scanned.processes_checked, 4);
});

// ---------- GitHub scanner ----------

test('github scanner: matches a repo name pattern', async () => {
  const iocs = await loadIocs();
  const result = await scanGithub(iocs, {
    repoList: async () => [
      { name: 'patient-zero', full_name: '0xSteph/patient-zero', description: 'totally legit' },
      { name: 'Shai-Hulud', full_name: '0xSteph/Shai-Hulud', description: 'i did not create this' },
      { name: 'my-side-project', full_name: '0xSteph/my-side-project', description: 'normal description' },
    ],
  });
  assert.equal(result.errors.length, 0);
  assert.equal(result.findings.length, 1);
  assert.equal(result.findings[0].artifact.repo, '0xSteph/Shai-Hulud');
  assert.ok(result.findings[0].artifact.reasons.some((r) => r.includes('name')));
});

test('github scanner: enabled=false returns immediately with skipped marker', async () => {
  const iocs = await loadIocs();
  const result = await scanGithub(iocs, { enabled: false });
  assert.equal(result.skipped, 'disabled by --no-github');
  assert.equal(result.findings.length, 0);
});

test('github scanner: list-failure is captured as error, not thrown', async () => {
  const iocs = await loadIocs();
  const result = await scanGithub(iocs, {
    repoList: async () => {
      throw new Error('simulated network failure');
    },
  });
  assert.equal(result.findings.length, 0);
  assert.equal(result.errors.length, 1);
  assert.match(result.errors[0], /simulated network failure/);
});
