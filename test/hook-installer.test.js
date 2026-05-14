import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, mkdir, writeFile, readFile, rm, stat } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { detectHookSystem, installHook, removeHook } from '../src/hook-installer.js';

async function makeGitRepo() {
  const dir = await mkdtemp(path.join(tmpdir(), 'p0-hook-'));
  await mkdir(path.join(dir, '.git/hooks'), { recursive: true });
  return dir;
}

// ---------- detectHookSystem ----------

test('detectHookSystem: returns native for a bare git repo', async () => {
  const dir = await makeGitRepo();
  try {
    assert.equal(detectHookSystem(dir), 'native');
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('detectHookSystem: returns husky when .husky/ exists', async () => {
  const dir = await makeGitRepo();
  try {
    await mkdir(path.join(dir, '.husky'), { recursive: true });
    assert.equal(detectHookSystem(dir), 'husky');
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('detectHookSystem: returns lefthook when lefthook.yml exists', async () => {
  const dir = await makeGitRepo();
  try {
    await writeFile(path.join(dir, 'lefthook.yml'), '', 'utf8');
    assert.equal(detectHookSystem(dir), 'lefthook');
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('detectHookSystem: returns pre-commit when .pre-commit-config.yaml exists', async () => {
  const dir = await makeGitRepo();
  try {
    await writeFile(path.join(dir, '.pre-commit-config.yaml'), '', 'utf8');
    assert.equal(detectHookSystem(dir), 'pre-commit');
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

// ---------- installHook ----------

test('installHook: native — creates executable .git/hooks/pre-commit when none exists', async () => {
  const dir = await makeGitRepo();
  try {
    const result = await installHook({ cwd: dir });
    assert.equal(result.system, 'native');
    assert.equal(result.action, 'created');
    const hookPath = path.join(dir, '.git/hooks/pre-commit');
    const body = await readFile(hookPath, 'utf8');
    assert.match(body, /^#!/m, 'shebang present');
    assert.match(body, /patient-zero/);
    // Skip exec-bit assertion on Windows — NTFS has no Unix permission bits.
    if (process.platform !== 'win32') {
      const st = await stat(hookPath);
      assert.equal(st.mode & 0o111, 0o111, 'executable bits set');
    }
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('installHook: native — idempotent (re-install replaces managed block only)', async () => {
  const dir = await makeGitRepo();
  try {
    await installHook({ cwd: dir });
    const after1 = await readFile(path.join(dir, '.git/hooks/pre-commit'), 'utf8');
    await installHook({ cwd: dir });
    const after2 = await readFile(path.join(dir, '.git/hooks/pre-commit'), 'utf8');
    assert.equal(after1, after2, 'second install must be a no-op');
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('installHook: native — preserves unrelated existing hook content', async () => {
  const dir = await makeGitRepo();
  try {
    const userHook = '#!/bin/sh\necho "my custom check"\nmake lint\n';
    await writeFile(path.join(dir, '.git/hooks/pre-commit'), userHook, 'utf8');
    await installHook({ cwd: dir });
    const after = await readFile(path.join(dir, '.git/hooks/pre-commit'), 'utf8');
    assert.match(after, /my custom check/);
    assert.match(after, /make lint/);
    assert.match(after, /patient-zero/);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('installHook: husky — creates .husky/pre-commit', async () => {
  const dir = await makeGitRepo();
  try {
    await mkdir(path.join(dir, '.husky'), { recursive: true });
    const result = await installHook({ cwd: dir });
    assert.equal(result.system, 'husky');
    const body = await readFile(path.join(dir, '.husky/pre-commit'), 'utf8');
    assert.match(body, /patient-zero/);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('installHook: lefthook — appends pre-commit entry', async () => {
  const dir = await makeGitRepo();
  try {
    await writeFile(path.join(dir, 'lefthook.yml'), 'pre-push:\n  commands:\n    test:\n      run: npm test\n', 'utf8');
    const result = await installHook({ cwd: dir });
    assert.equal(result.system, 'lefthook');
    const body = await readFile(path.join(dir, 'lefthook.yml'), 'utf8');
    assert.match(body, /patient-zero/);
    assert.match(body, /pre-commit:/);
    assert.match(body, /pre-push:/, 'must preserve existing pre-push config');
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('installHook: pre-commit — appends a local repo entry', async () => {
  const dir = await makeGitRepo();
  try {
    await writeFile(path.join(dir, '.pre-commit-config.yaml'), 'repos:\n- repo: https://github.com/example/repo\n  rev: v1\n  hooks: []\n', 'utf8');
    const result = await installHook({ cwd: dir });
    assert.equal(result.system, 'pre-commit');
    const body = await readFile(path.join(dir, '.pre-commit-config.yaml'), 'utf8');
    assert.match(body, /patient-zero/);
    assert.match(body, /local/);
    assert.match(body, /repos:/, 'must preserve existing repos: header');
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('installHook: explicit --system override beats auto-detect', async () => {
  const dir = await makeGitRepo();
  try {
    await mkdir(path.join(dir, '.husky'), { recursive: true });
    // Auto-detect would say husky; force native.
    const result = await installHook({ cwd: dir, system: 'native' });
    assert.equal(result.system, 'native');
    assert.equal(result.path, '.git/hooks/pre-commit');
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('installHook: errors when cwd is not a git repository', async () => {
  const dir = await mkdtemp(path.join(tmpdir(), 'p0-nongit-'));
  try {
    await assert.rejects(installHook({ cwd: dir }), /not a git repository/);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

// ---------- removeHook ----------

test('removeHook: removes managed block from native hook, preserving user content', async () => {
  const dir = await makeGitRepo();
  try {
    const userHook = '#!/bin/sh\necho "my own thing"\n';
    await writeFile(path.join(dir, '.git/hooks/pre-commit'), userHook, 'utf8');
    await installHook({ cwd: dir });
    const result = await removeHook({ cwd: dir });
    assert.ok(result.removed.length >= 1);
    const after = await readFile(path.join(dir, '.git/hooks/pre-commit'), 'utf8');
    assert.match(after, /my own thing/);
    assert.doesNotMatch(after, /patient-zero/);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('removeHook: deletes hook file entirely if it had only our content', async () => {
  const dir = await makeGitRepo();
  try {
    await installHook({ cwd: dir });
    const result = await removeHook({ cwd: dir });
    assert.ok(result.removed.includes('.git/hooks/pre-commit'));
    // File should be gone
    await assert.rejects(stat(path.join(dir, '.git/hooks/pre-commit')));
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('removeHook: no-op when no patient-zero hook is installed', async () => {
  const dir = await makeGitRepo();
  try {
    const result = await removeHook({ cwd: dir });
    assert.equal(result.removed.length, 0);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});
