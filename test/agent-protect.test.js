import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, mkdir, readFile, writeFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { detectAgents, protectAgents, unprotectAgents } from '../src/agent-hook-installer.js';

async function makeHome(withDirs = []) {
  const dir = await mkdtemp(path.join(tmpdir(), 'p0-protect-'));
  for (const d of withDirs) await mkdir(path.join(dir, d), { recursive: true });
  return dir;
}

// ---------- detectAgents ----------

test('detectAgents: finds claude-code and cursor from config dirs', async () => {
  const home = await makeHome(['.claude', '.cursor']);
  const cwd = await makeHome();
  try {
    assert.deepEqual(detectAgents({ home, cwd }), ['claude-code', 'cursor']);
    assert.deepEqual(detectAgents({ home: cwd, cwd }), []);
  } finally {
    await rm(home, { recursive: true, force: true });
    await rm(cwd, { recursive: true, force: true });
  }
});

// ---------- protectAgents: claude-code ----------

test('protect claude-code: creates settings.json with PreToolUse Bash hook', async () => {
  const home = await makeHome(['.claude']);
  try {
    const { installed } = await protectAgents({ agents: ['claude-code'], home, cwd: home });
    assert.equal(installed[0].action, 'created');
    const settings = JSON.parse(await readFile(path.join(home, '.claude/settings.json'), 'utf8'));
    const entry = settings.hooks.PreToolUse[0];
    assert.equal(entry.matcher, 'Bash');
    assert.match(entry.hooks[0].command, /patient-zero@latest guard --agent claude-code/);
  } finally {
    await rm(home, { recursive: true, force: true });
  }
});

test('protect claude-code: preserves existing settings and is idempotent', async () => {
  const home = await makeHome(['.claude']);
  try {
    await writeFile(
      path.join(home, '.claude/settings.json'),
      JSON.stringify({
        model: 'opus',
        hooks: { PreToolUse: [{ matcher: 'Write', hooks: [{ type: 'command', command: 'my-linter' }] }] },
      }),
      'utf8',
    );
    await protectAgents({ agents: ['claude-code'], home, cwd: home });
    const second = await protectAgents({ agents: ['claude-code'], home, cwd: home });
    assert.equal(second.installed[0].action, 'unchanged');

    const settings = JSON.parse(await readFile(path.join(home, '.claude/settings.json'), 'utf8'));
    assert.equal(settings.model, 'opus');
    assert.equal(settings.hooks.PreToolUse.length, 2);
    assert.equal(settings.hooks.PreToolUse[0].hooks[0].command, 'my-linter');
  } finally {
    await rm(home, { recursive: true, force: true });
  }
});

// ---------- protectAgents: cursor ----------

test('protect cursor: creates hooks.json with beforeShellExecution', async () => {
  const home = await makeHome(['.cursor']);
  try {
    await protectAgents({ agents: ['cursor'], home, cwd: home });
    const config = JSON.parse(await readFile(path.join(home, '.cursor/hooks.json'), 'utf8'));
    assert.equal(config.version, 1);
    assert.match(config.hooks.beforeShellExecution[0].command, /guard --agent cursor/);
  } finally {
    await rm(home, { recursive: true, force: true });
  }
});

// ---------- scope + remove ----------

test('protect --project writes into cwd, not home', async () => {
  const home = await makeHome();
  const cwd = await makeHome(['.claude']);
  try {
    const { installed } = await protectAgents({ agents: ['claude-code'], scope: 'project', home, cwd });
    assert.ok(installed[0].path.startsWith(cwd));
  } finally {
    await rm(home, { recursive: true, force: true });
    await rm(cwd, { recursive: true, force: true });
  }
});

test('unprotect removes only our entries, leaves the rest intact', async () => {
  const home = await makeHome(['.claude', '.cursor']);
  try {
    await writeFile(
      path.join(home, '.claude/settings.json'),
      JSON.stringify({
        hooks: { PreToolUse: [{ matcher: 'Write', hooks: [{ type: 'command', command: 'my-linter' }] }] },
      }),
      'utf8',
    );
    await protectAgents({ agents: ['claude-code', 'cursor'], home, cwd: home });
    const { removed } = await unprotectAgents({ home, cwd: home });
    assert.equal(removed.length, 2);

    const settings = JSON.parse(await readFile(path.join(home, '.claude/settings.json'), 'utf8'));
    assert.equal(settings.hooks.PreToolUse.length, 1);
    assert.equal(settings.hooks.PreToolUse[0].hooks[0].command, 'my-linter');

    const cursor = JSON.parse(await readFile(path.join(home, '.cursor/hooks.json'), 'utf8'));
    assert.equal(cursor.hooks.beforeShellExecution.length, 0);

    // second remove is a no-op
    const again = await unprotectAgents({ home, cwd: home });
    assert.equal(again.removed.length, 0);
  } finally {
    await rm(home, { recursive: true, force: true });
  }
});
