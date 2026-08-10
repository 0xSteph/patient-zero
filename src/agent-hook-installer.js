import { existsSync } from 'node:fs';
import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { homedir } from 'node:os';
import path from 'node:path';

/**
 * `patient-zero protect` — wire the guard into AI coding agents so package
 * installs the agent runs (including in auto / skip-permissions mode) are
 * scanned before they execute.
 *
 * Supported agents:
 *   - Claude Code: PreToolUse hook on the Bash tool, via settings.json
 *   - Cursor:      beforeShellExecution hook, via hooks.json
 *
 * All edits are marker-identified (our command string contains
 * "patient-zero guard"), idempotent, and reversible with --remove. We never
 * touch entries we didn't create.
 */

const GUARD_REGEX = /patient-zero(@\S+)?\s+guard/;
const isGuardCommand = (cmd) => typeof cmd === 'string' && GUARD_REGEX.test(cmd);
const CLAUDE_GUARD_COMMAND = 'npx -y patient-zero@latest guard --agent claude-code';
const CURSOR_GUARD_COMMAND = 'npx -y patient-zero@latest guard --agent cursor';
const HOOK_TIMEOUT_SECONDS = 120;

/**
 * Detect which agents are present on this machine / in this project.
 *
 * @param {{ home?: string, cwd?: string }} [options]
 * @returns {Array<'claude-code'|'cursor'>}
 */
export function detectAgents(options = {}) {
  const home = options.home ?? homedir();
  const cwd = options.cwd ?? process.cwd();
  const agents = [];
  if (
    existsSync(path.join(home, '.claude')) ||
    existsSync(path.join(cwd, '.claude'))
  ) agents.push('claude-code');
  if (
    existsSync(path.join(home, '.cursor')) ||
    existsSync(path.join(cwd, '.cursor'))
  ) agents.push('cursor');
  return agents;
}

/**
 * Install the guard hook for the given agents (default: all detected).
 *
 * @param {{ agents?: string[], scope?: 'user'|'project', home?: string, cwd?: string }} [options]
 * @returns {Promise<{ installed: Array<{agent: string, path: string, action: 'created'|'updated'|'unchanged'}>, detected: string[] }>}
 */
export async function protectAgents(options = {}) {
  const home = options.home ?? homedir();
  const cwd = options.cwd ?? process.cwd();
  const scope = options.scope ?? 'user';
  const detected = detectAgents({ home, cwd });
  const targets = options.agents?.length ? options.agents : detected;

  const installed = [];
  for (const agent of targets) {
    if (agent === 'claude-code') {
      installed.push(await installClaudeCode({ home, cwd, scope }));
    } else if (agent === 'cursor') {
      installed.push(await installCursor({ home, cwd, scope }));
    } else {
      throw new Error(`unsupported agent: ${agent} (supported: claude-code, cursor)`);
    }
  }
  return { installed, detected };
}

/**
 * Remove any guard hooks we previously installed, in both scopes.
 *
 * @param {{ home?: string, cwd?: string }} [options]
 * @returns {Promise<{ removed: Array<{agent: string, path: string}> }>}
 */
export async function unprotectAgents(options = {}) {
  const home = options.home ?? homedir();
  const cwd = options.cwd ?? process.cwd();
  const removed = [];

  for (const settingsPath of [
    path.join(home, '.claude', 'settings.json'),
    path.join(cwd, '.claude', 'settings.json'),
  ]) {
    if (!existsSync(settingsPath)) continue;
    const settings = JSON.parse(await readFile(settingsPath, 'utf8'));
    if (stripClaudeGuard(settings)) {
      await writeFile(settingsPath, JSON.stringify(settings, null, 2) + '\n', 'utf8');
      removed.push({ agent: 'claude-code', path: settingsPath });
    }
  }

  for (const hooksPath of [
    path.join(home, '.cursor', 'hooks.json'),
    path.join(cwd, '.cursor', 'hooks.json'),
  ]) {
    if (!existsSync(hooksPath)) continue;
    const config = JSON.parse(await readFile(hooksPath, 'utf8'));
    if (stripCursorGuard(config)) {
      await writeFile(hooksPath, JSON.stringify(config, null, 2) + '\n', 'utf8');
      removed.push({ agent: 'cursor', path: hooksPath });
    }
  }

  return { removed };
}

// ---------- Claude Code (settings.json → hooks.PreToolUse) ----------

async function installClaudeCode({ home, cwd, scope }) {
  const dir = scope === 'project' ? path.join(cwd, '.claude') : path.join(home, '.claude');
  const settingsPath = path.join(dir, 'settings.json');

  let settings = {};
  const existed = existsSync(settingsPath);
  if (existed) {
    settings = JSON.parse(await readFile(settingsPath, 'utf8'));
  }

  settings.hooks ??= {};
  settings.hooks.PreToolUse ??= [];
  if (!Array.isArray(settings.hooks.PreToolUse)) {
    throw new Error(`${settingsPath}: hooks.PreToolUse is not an array — refusing to modify`);
  }

  const guardHook = {
    type: 'command',
    command: CLAUDE_GUARD_COMMAND,
    timeout: HOOK_TIMEOUT_SECONDS,
  };

  // Find an existing matcher entry that carries our guard.
  let action = 'created';
  const existing = settings.hooks.PreToolUse.find((entry) =>
    entry?.hooks?.some((h) => isGuardCommand(h?.command)),
  );
  if (existing) {
    const idx = existing.hooks.findIndex((h) => isGuardCommand(h?.command));
    if (JSON.stringify(existing.hooks[idx]) === JSON.stringify(guardHook) && existing.matcher === 'Bash') {
      action = 'unchanged';
    } else {
      existing.matcher = 'Bash';
      existing.hooks[idx] = guardHook;
      action = 'updated';
    }
  } else {
    settings.hooks.PreToolUse.push({ matcher: 'Bash', hooks: [guardHook] });
  }

  if (action !== 'unchanged') {
    await mkdir(dir, { recursive: true });
    await writeFile(settingsPath, JSON.stringify(settings, null, 2) + '\n', 'utf8');
  }
  return { agent: 'claude-code', path: settingsPath, action };
}

function stripClaudeGuard(settings) {
  const pre = settings?.hooks?.PreToolUse;
  if (!Array.isArray(pre)) return false;
  let changed = false;
  for (const entry of pre) {
    if (!Array.isArray(entry?.hooks)) continue;
    const before = entry.hooks.length;
    entry.hooks = entry.hooks.filter((h) => !isGuardCommand(h?.command));
    if (entry.hooks.length !== before) changed = true;
  }
  settings.hooks.PreToolUse = pre.filter((entry) => !Array.isArray(entry?.hooks) || entry.hooks.length > 0);
  return changed;
}

// ---------- Cursor (hooks.json → beforeShellExecution) ----------

async function installCursor({ home, cwd, scope }) {
  const dir = scope === 'project' ? path.join(cwd, '.cursor') : path.join(home, '.cursor');
  const hooksPath = path.join(dir, 'hooks.json');

  let config = { version: 1, hooks: {} };
  const existed = existsSync(hooksPath);
  if (existed) {
    config = JSON.parse(await readFile(hooksPath, 'utf8'));
  }
  config.version ??= 1;
  config.hooks ??= {};
  config.hooks.beforeShellExecution ??= [];
  if (!Array.isArray(config.hooks.beforeShellExecution)) {
    throw new Error(`${hooksPath}: hooks.beforeShellExecution is not an array — refusing to modify`);
  }

  let action = 'created';
  const idx = config.hooks.beforeShellExecution.findIndex(
    (h) => isGuardCommand(h?.command),
  );
  if (idx >= 0) {
    if (config.hooks.beforeShellExecution[idx].command === CURSOR_GUARD_COMMAND) {
      action = 'unchanged';
    } else {
      config.hooks.beforeShellExecution[idx] = { command: CURSOR_GUARD_COMMAND };
      action = 'updated';
    }
  } else {
    config.hooks.beforeShellExecution.push({ command: CURSOR_GUARD_COMMAND });
  }

  if (action !== 'unchanged') {
    await mkdir(dir, { recursive: true });
    await writeFile(hooksPath, JSON.stringify(config, null, 2) + '\n', 'utf8');
  }
  return { agent: 'cursor', path: hooksPath, action };
}

function stripCursorGuard(config) {
  const arr = config?.hooks?.beforeShellExecution;
  if (!Array.isArray(arr)) return false;
  const before = arr.length;
  config.hooks.beforeShellExecution = arr.filter((h) => !isGuardCommand(h?.command));
  return config.hooks.beforeShellExecution.length !== before;
}
