import { existsSync } from 'node:fs';
import { mkdir, readFile, writeFile, chmod, unlink, stat } from 'node:fs/promises';
import path from 'node:path';

const HUSKY_DIR = '.husky';
const HUSKY_HOOK_PATH = '.husky/pre-commit';
const NATIVE_HOOK_PATH = '.git/hooks/pre-commit';
const LEFTHOOK_FILE = 'lefthook.yml';
const PRE_COMMIT_CONFIG = '.pre-commit-config.yaml';

const PATIENT_ZERO_MARKER_START = '# >>> patient-zero hook (managed by `npx patient-zero install-hook`) >>>';
const PATIENT_ZERO_MARKER_END = '# <<< patient-zero hook <<<';
const HOOK_COMMAND = 'npx patient-zero@latest scan --no-github --ecosystem npm --offline';

/**
 * Detect which pre-commit ecosystem is in use in `cwd`. Picks the highest-leverage
 * existing system; falls back to a native git hook if none is present.
 *
 * @param {string} cwd
 * @returns {'husky'|'lefthook'|'pre-commit'|'native'}
 */
export function detectHookSystem(cwd) {
  if (existsSync(path.join(cwd, HUSKY_DIR))) return 'husky';
  if (existsSync(path.join(cwd, LEFTHOOK_FILE))) return 'lefthook';
  if (existsSync(path.join(cwd, PRE_COMMIT_CONFIG))) return 'pre-commit';
  return 'native';
}

/**
 * Install the patient-zero hook into the detected (or specified) hook system.
 * Idempotent — re-installing replaces our managed block without disturbing
 * unrelated hook content.
 *
 * @param {{ cwd?: string, system?: 'husky'|'lefthook'|'pre-commit'|'native' }} [options]
 * @returns {Promise<{ system: string, path: string, action: 'created'|'updated', existedAlready: boolean }>}
 */
export async function installHook(options = {}) {
  const cwd = options.cwd ?? process.cwd();

  if (!existsSync(path.join(cwd, '.git'))) {
    throw new Error('not a git repository — run `git init` first');
  }

  const system = options.system ?? detectHookSystem(cwd);

  switch (system) {
    case 'husky':
      return installHusky(cwd);
    case 'lefthook':
      return installLefthook(cwd);
    case 'pre-commit':
      return installPreCommit(cwd);
    case 'native':
      return installNative(cwd);
    default:
      throw new Error(`unknown hook system: ${system}`);
  }
}

/**
 * Remove the patient-zero managed block from whichever system has it. Leaves
 * other hook content intact.
 *
 * @param {{ cwd?: string }} [options]
 * @returns {Promise<{ removed: string[] }>}
 */
export async function removeHook(options = {}) {
  const cwd = options.cwd ?? process.cwd();
  const removed = [];

  for (const p of [HUSKY_HOOK_PATH, NATIVE_HOOK_PATH]) {
    const full = path.join(cwd, p);
    if (existsSync(full)) {
      const updated = stripManagedBlock(await readFile(full, 'utf8'));
      if (updated === null) {
        await unlink(full);
        removed.push(p);
      } else {
        await writeFile(full, updated, 'utf8');
        removed.push(`${p} (block stripped)`);
      }
    }
  }

  if (existsSync(path.join(cwd, LEFTHOOK_FILE))) {
    const raw = await readFile(path.join(cwd, LEFTHOOK_FILE), 'utf8');
    const updated = stripLefthookEntry(raw);
    if (updated !== raw) {
      await writeFile(path.join(cwd, LEFTHOOK_FILE), updated, 'utf8');
      removed.push(`${LEFTHOOK_FILE} (entry stripped)`);
    }
  }

  if (existsSync(path.join(cwd, PRE_COMMIT_CONFIG))) {
    const raw = await readFile(path.join(cwd, PRE_COMMIT_CONFIG), 'utf8');
    const updated = stripPreCommitEntry(raw);
    if (updated !== raw) {
      await writeFile(path.join(cwd, PRE_COMMIT_CONFIG), updated, 'utf8');
      removed.push(`${PRE_COMMIT_CONFIG} (entry stripped)`);
    }
  }

  return { removed };
}

// ---------- husky ----------

async function installHusky(cwd) {
  const hookPath = path.join(cwd, HUSKY_HOOK_PATH);
  const existed = existsSync(hookPath);
  const current = existed ? await readFile(hookPath, 'utf8') : '';
  const next = upsertManagedBlock(current, husbandBlock());
  await mkdir(path.dirname(hookPath), { recursive: true });
  await writeFile(hookPath, next, 'utf8');
  await chmod(hookPath, 0o755);
  return {
    system: 'husky',
    path: HUSKY_HOOK_PATH,
    action: existed ? 'updated' : 'created',
    existedAlready: existed,
  };
}

function husbandBlock() {
  return [
    PATIENT_ZERO_MARKER_START,
    HOOK_COMMAND,
    PATIENT_ZERO_MARKER_END,
  ].join('\n');
}

// ---------- native ----------

async function installNative(cwd) {
  const hookPath = path.join(cwd, NATIVE_HOOK_PATH);
  const existed = existsSync(hookPath);
  const current = existed ? await readFile(hookPath, 'utf8') : '#!/bin/sh\n';
  const next = upsertManagedBlock(current, husbandBlock());
  await mkdir(path.dirname(hookPath), { recursive: true });
  // Ensure shebang
  const final = next.startsWith('#!') ? next : '#!/bin/sh\n' + next;
  await writeFile(hookPath, final, 'utf8');
  await chmod(hookPath, 0o755);
  return {
    system: 'native',
    path: NATIVE_HOOK_PATH,
    action: existed ? 'updated' : 'created',
    existedAlready: existed,
  };
}

// ---------- lefthook ----------

async function installLefthook(cwd) {
  const filePath = path.join(cwd, LEFTHOOK_FILE);
  const raw = await readFile(filePath, 'utf8');
  if (raw.includes('patient-zero')) {
    return { system: 'lefthook', path: LEFTHOOK_FILE, action: 'updated', existedAlready: true };
  }
  // Append a pre-commit entry under the pre-commit > commands key. We do a
  // textual append; users with complex lefthook configs may want to install
  // manually. Document this in the output.
  const block = [
    '',
    '# Added by `npx patient-zero install-hook`',
    'pre-commit:',
    '  commands:',
    '    patient-zero:',
    `      run: ${HOOK_COMMAND}`,
    '',
  ].join('\n');
  await writeFile(filePath, raw + block, 'utf8');
  return { system: 'lefthook', path: LEFTHOOK_FILE, action: 'updated', existedAlready: false };
}

// ---------- pre-commit (the python tool) ----------

async function installPreCommit(cwd) {
  const filePath = path.join(cwd, PRE_COMMIT_CONFIG);
  const raw = await readFile(filePath, 'utf8');
  if (raw.includes('patient-zero')) {
    return { system: 'pre-commit', path: PRE_COMMIT_CONFIG, action: 'updated', existedAlready: true };
  }
  const block = [
    '',
    '# Added by `npx patient-zero install-hook`',
    '- repo: local',
    '  hooks:',
    '    - id: patient-zero',
    '      name: patient-zero supply-chain scan',
    '      language: system',
    `      entry: ${HOOK_COMMAND}`,
    '      pass_filenames: false',
    '',
  ].join('\n');
  await writeFile(filePath, raw + block, 'utf8');
  return { system: 'pre-commit', path: PRE_COMMIT_CONFIG, action: 'updated', existedAlready: false };
}

// ---------- managed-block edit helpers ----------

function upsertManagedBlock(existing, block) {
  if (existing.includes(PATIENT_ZERO_MARKER_START)) {
    const before = existing.slice(0, existing.indexOf(PATIENT_ZERO_MARKER_START));
    const afterIdx = existing.indexOf(PATIENT_ZERO_MARKER_END);
    if (afterIdx < 0) return existing + '\n' + block + '\n';
    const after = existing.slice(afterIdx + PATIENT_ZERO_MARKER_END.length);
    return (before + block + after).replace(/\n{3,}/g, '\n\n');
  }
  const sep = existing.length === 0 || existing.endsWith('\n') ? '' : '\n';
  return existing + sep + (existing.length > 0 ? '\n' : '') + block + '\n';
}

function stripManagedBlock(existing) {
  if (!existing.includes(PATIENT_ZERO_MARKER_START)) return existing;
  const before = existing.slice(0, existing.indexOf(PATIENT_ZERO_MARKER_START));
  const afterIdx = existing.indexOf(PATIENT_ZERO_MARKER_END);
  const after = afterIdx >= 0 ? existing.slice(afterIdx + PATIENT_ZERO_MARKER_END.length) : '';
  const result = (before + after).replace(/\n{3,}/g, '\n\n').trim();
  // If the file would be empty (or just shebang), signal deletion to caller
  if (result === '' || result === '#!/bin/sh') return null;
  return result + '\n';
}

function stripLefthookEntry(raw) {
  // Remove a contiguous block we added that starts at the comment marker and
  // ends with the last 'run:' line for patient-zero. Conservative — if we
  // can't identify our exact block, we leave the file alone.
  const startMarker = '# Added by `npx patient-zero install-hook`';
  const idx = raw.indexOf(startMarker);
  if (idx < 0) return raw;
  const before = raw.slice(0, idx);
  // Find the end: the line containing patient-zero's run command, then end of block
  const tail = raw.slice(idx);
  const runIdx = tail.indexOf('patient-zero:');
  if (runIdx < 0) return raw;
  // From the start of our block, eat until the next blank line or EOF
  const remainder = tail.slice(runIdx);
  const blank = remainder.search(/\n\s*\n/);
  const end = blank < 0 ? remainder.length : blank;
  const after = remainder.slice(end);
  return (before + after).replace(/\n{3,}/g, '\n\n');
}

function stripPreCommitEntry(raw) {
  const startMarker = '# Added by `npx patient-zero install-hook`';
  const idx = raw.indexOf(startMarker);
  if (idx < 0) return raw;
  const before = raw.slice(0, idx);
  // Eat until next top-level YAML key (line starting with non-space, non-dash) or EOF
  const tail = raw.slice(idx);
  const lines = tail.split('\n');
  let i = 0;
  while (i < lines.length) {
    i += 1;
    if (i >= lines.length) break;
    const l = lines[i];
    if (l && !l.startsWith(' ') && !l.startsWith('-') && !l.startsWith('#') && l.trim() !== '') break;
  }
  const consumed = lines.slice(0, i).join('\n');
  const after = tail.slice(consumed.length);
  return (before + after).replace(/\n{3,}/g, '\n\n');
}
