import { loadIocs } from './ioc-loader.js';
import { matchTreeAgainstIocs } from './install-interceptor.js';
import { parsePackageSpec, runHeuristics, DEFAULT_COOLDOWN_HOURS } from './heuristics.js';

/**
 * Agent guard: the runtime half of `patient-zero protect`.
 *
 * An AI coding agent (Claude Code, Cursor) is about to run a shell command.
 * The agent's hook system hands us the command; we decide allow/deny. This
 * must be fast (it runs on every Bash call) and it must FAIL OPEN — a broken
 * scanner should never brick someone's dev loop. Denials return a
 * machine-readable reason the agent can act on (e.g. "install the previous
 * stable version instead"), which is what turns a block into a self-correction.
 */

// Severities at or above this rank cause a deny.
const BLOCK_SEVERITIES = new Set(['critical', 'high', 'medium']);

/**
 * Parse a shell command string into the package-install operations it contains.
 * Handles chained commands (&&, ;, ||, |) conservatively: every segment is
 * inspected independently.
 *
 * @param {string} command
 * @returns {Array<{ pm: string, ecosystem: 'npm'|'pypi', packages: Array<{name: string, spec: string|null}>, bare: boolean, segment: string }>}
 */
export function parseInstallCommands(command) {
  const ops = [];
  if (!command || typeof command !== 'string') return ops;

  for (const segment of splitSegments(command)) {
    const tokens = tokenize(segment);
    if (tokens.length === 0) continue;
    const op = classifySegment(tokens, segment);
    if (op) ops.push(op);
  }
  return ops;
}

function splitSegments(command) {
  // Split on shell control operators outside of quotes.
  const segments = [];
  let cur = '';
  let quote = null;
  for (let i = 0; i < command.length; i++) {
    const ch = command[i];
    if (quote) {
      cur += ch;
      if (ch === quote && command[i - 1] !== '\\') quote = null;
      continue;
    }
    if (ch === '"' || ch === "'") {
      quote = ch;
      cur += ch;
      continue;
    }
    if (ch === '&' || ch === '|' || ch === ';' || ch === '\n') {
      if (cur.trim()) segments.push(cur.trim());
      cur = '';
      // skip doubled operator char
      if ((ch === '&' || ch === '|') && command[i + 1] === ch) i++;
      continue;
    }
    cur += ch;
  }
  if (cur.trim()) segments.push(cur.trim());
  return segments;
}

function tokenize(segment) {
  const tokens = [];
  const re = /"([^"]*)"|'([^']*)'|(\S+)/g;
  let m;
  while ((m = re.exec(segment)) !== null) {
    tokens.push(m[1] ?? m[2] ?? m[3]);
  }
  return tokens;
}

function classifySegment(tokens, segment) {
  // Strip leading env assignments (FOO=bar cmd ...) and common wrappers.
  let t = [...tokens];
  while (t.length && /^[A-Za-z_][A-Za-z0-9_]*=/.test(t[0])) t.shift();
  while (t.length && ['sudo', 'command', 'exec'].includes(t[0])) t.shift();
  if (t.length === 0) return null;

  const cmd = t[0];
  const rest = t.slice(1);

  const collectArgs = (args, { stopFlagsWithValue = [] } = {}) => {
    const pkgs = [];
    for (let i = 0; i < args.length; i++) {
      const a = args[i];
      if (a.startsWith('-')) {
        if (stopFlagsWithValue.includes(a)) i++; // skip flag value
        continue;
      }
      pkgs.push(a);
    }
    return pkgs;
  };

  if (cmd === 'npm') {
    const sub = rest[0];
    if (['install', 'i', 'in', 'ins', 'add', 'isntall'].includes(sub)) {
      const raw = collectArgs(rest.slice(1), { stopFlagsWithValue: ['--registry', '--prefix', '-w', '--workspace'] });
      return npmOp('npm', raw, segment);
    }
    if (sub === 'ci') return { pm: 'npm', ecosystem: 'npm', packages: [], bare: true, segment };
    if (sub === 'exec') {
      const raw = collectArgs(rest.slice(1)).slice(0, 1);
      return raw.length ? npmOp('npm exec', raw, segment) : null;
    }
    return null;
  }

  if (cmd === 'npx') {
    const raw = collectArgs(rest, { stopFlagsWithValue: ['-p', '--package'] }).slice(0, 1);
    // also pick up explicit -p/--package values
    for (let i = 0; i < rest.length; i++) {
      if (rest[i] === '-p' || rest[i] === '--package') raw.push(rest[i + 1]);
    }
    return raw.length ? npmOp('npx', raw.filter(Boolean), segment) : null;
  }

  if (cmd === 'pnpm') {
    const sub = rest[0];
    if (['add', 'install', 'i'].includes(sub)) {
      const raw = collectArgs(rest.slice(1), { stopFlagsWithValue: ['--filter', '-C', '--dir'] });
      return raw.length || sub !== 'add'
        ? npmOp('pnpm', raw, segment)
        : null;
    }
    if (sub === 'dlx') {
      const raw = collectArgs(rest.slice(1)).slice(0, 1);
      return raw.length ? npmOp('pnpm dlx', raw, segment) : null;
    }
    return null;
  }

  if (cmd === 'yarn') {
    const sub = rest[0];
    if (sub === 'add') return npmOp('yarn', collectArgs(rest.slice(1)), segment);
    if (sub === undefined || sub === 'install') return { pm: 'yarn', ecosystem: 'npm', packages: [], bare: true, segment };
    if (sub === 'dlx') {
      const raw = collectArgs(rest.slice(1)).slice(0, 1);
      return raw.length ? npmOp('yarn dlx', raw, segment) : null;
    }
    return null;
  }

  if (cmd === 'bun') {
    const sub = rest[0];
    if (['add', 'install', 'i'].includes(sub)) return npmOp('bun', collectArgs(rest.slice(1)), segment);
    return null;
  }
  if (cmd === 'bunx') {
    const raw = collectArgs(rest).slice(0, 1);
    return raw.length ? npmOp('bunx', raw, segment) : null;
  }

  if (cmd === 'pip' || cmd === 'pip3' || cmd === 'pipx') {
    if (rest[0] === 'install') {
      const args = rest.slice(1);
      // `pip install -r requirements.txt` → bare (lockfile-style) install
      if (args.includes('-r') || args.includes('--requirement')) {
        return { pm: cmd, ecosystem: 'pypi', packages: [], bare: true, segment };
      }
      const raw = collectArgs(args, { stopFlagsWithValue: ['--index-url', '-i', '--extra-index-url', '--target', '-t'] });
      return pypiOp(cmd, raw, segment);
    }
    return null;
  }

  if (cmd === 'uv') {
    if (rest[0] === 'add') return pypiOp('uv', collectArgs(rest.slice(1)), segment);
    if (rest[0] === 'pip' && rest[1] === 'install') {
      const args = rest.slice(2);
      if (args.includes('-r') || args.includes('--requirement')) {
        return { pm: 'uv pip', ecosystem: 'pypi', packages: [], bare: true, segment };
      }
      return pypiOp('uv pip', collectArgs(args, { stopFlagsWithValue: ['--index-url', '-i'] }), segment);
    }
    if (rest[0] === 'tool' && rest[1] === 'install') return pypiOp('uv tool', collectArgs(rest.slice(2)), segment);
    return null;
  }

  if (cmd === 'poetry' && rest[0] === 'add') {
    return pypiOp('poetry', collectArgs(rest.slice(1)), segment);
  }

  return null;
}

function npmOp(pm, raw, segment) {
  const packages = raw
    .filter((r) => !r.startsWith('.') && !r.startsWith('/') && !r.startsWith('file:') && !r.includes('://'))
    .map((r) => parsePackageSpec(r, 'npm'));
  return { pm, ecosystem: 'npm', packages, bare: packages.length === 0, segment };
}

function pypiOp(pm, raw, segment) {
  const packages = raw
    .filter((r) => !r.startsWith('.') && !r.startsWith('/') && !r.includes('://'))
    .map((r) => parsePackageSpec(r, 'pypi'));
  if (packages.length === 0) return null;
  return { pm, ecosystem: 'pypi', packages, bare: false, segment };
}

/**
 * Evaluate a shell command an agent wants to run.
 *
 * @param {string} command
 * @param {{ offline?: boolean, cooldownHours?: number, noHeuristics?: boolean, fetchFn?: typeof fetch }} [options]
 * @returns {Promise<{ decision: 'allow'|'deny', reason: string|null, iocFindings: Array, heuristicFindings: Array, ops: Array }>}
 */
export async function evaluateCommand(command, options = {}) {
  const ops = parseInstallCommands(command);
  if (ops.length === 0) {
    return { decision: 'allow', reason: null, iocFindings: [], heuristicFindings: [], ops };
  }

  // Only load the IoC DB when the command actually installs something.
  const { iocs } = await loadIocs({ offline: Boolean(options.offline) });

  const iocFindings = [];
  const heuristicFindings = [];

  for (const op of ops) {
    if (op.packages.length > 0) {
      const entries = op.packages.map((p) => ({
        name: p.name,
        version: p.spec && /^\d/.test(p.spec) ? p.spec : '*',
        ecosystem: op.ecosystem,
      }));
      iocFindings.push(...matchTreeAgainstIocs(entries, iocs));

      if (!options.noHeuristics) {
        const { findings } = await runHeuristics(op.packages, op.ecosystem, {
          offline: options.offline,
          cooldownHours: options.cooldownHours ?? DEFAULT_COOLDOWN_HOURS,
          fetchFn: options.fetchFn,
        });
        heuristicFindings.push(...findings);
      }
    }
  }

  const blockingIoc = iocFindings.filter((f) => BLOCK_SEVERITIES.has(f.indicator.severity));
  const blockingHeuristic = heuristicFindings.filter((f) => BLOCK_SEVERITIES.has(f.severity));

  if (blockingIoc.length === 0 && blockingHeuristic.length === 0) {
    return { decision: 'allow', reason: null, iocFindings, heuristicFindings, ops };
  }

  return {
    decision: 'deny',
    reason: renderReason(blockingIoc, blockingHeuristic),
    iocFindings,
    heuristicFindings,
    ops,
  };
}

function renderReason(iocFindings, heuristicFindings) {
  const lines = ['patient-zero blocked this install before any package scripts ran.'];
  for (const f of iocFindings) {
    lines.push(
      `- [${f.indicator.severity.toUpperCase()}] ${f.artifact.name}@${f.artifact.version} matches known-attack indicator ${f.indicator.id} (${f.indicator.attack_family}). ${f.indicator.description ?? ''}`.trim(),
    );
    const steps = f.indicator.remediation?.what_to_do;
    if (steps?.length) lines.push(`  Next step: ${steps[0]}`);
  }
  for (const f of heuristicFindings) {
    lines.push(`- [${f.severity.toUpperCase()}] ${f.message}`);
    if (f.suggestion) lines.push(`  Next step: ${f.suggestion}`);
  }
  lines.push(
    'Tell the user what was blocked and why. If they explicitly confirm they trust the package, they can bypass patient-zero by running the install manually.',
  );
  return lines.join('\n');
}

/**
 * Run the guard against a hook payload from stdin, printing the response the
 * calling agent expects. Never throws: internal errors fail open (allow).
 *
 * @param {'claude-code'|'cursor'} agent
 * @param {string} stdinText raw hook payload
 * @param {{ offline?: boolean, cooldownHours?: number, noHeuristics?: boolean, fetchFn?: typeof fetch }} [options]
 * @returns {Promise<{ output: string, exitCode: number, decision: string }>}
 */
export async function runGuard(agent, stdinText, options = {}) {
  let command = '';
  try {
    const payload = JSON.parse(stdinText || '{}');
    if (agent === 'cursor') {
      command = payload.command ?? '';
    } else {
      // claude-code PreToolUse payload
      if (payload.tool_name && payload.tool_name !== 'Bash') {
        return allowResponse(agent, 'non-bash tool');
      }
      command = payload.tool_input?.command ?? '';
    }
  } catch {
    return allowResponse(agent, 'unparseable payload');
  }

  let result;
  try {
    result = await evaluateCommand(command, options);
  } catch (err) {
    // Fail open — but say so on stderr for debuggability.
    process.stderr.write(`patient-zero guard: internal error (allowing): ${err.message}\n`);
    return allowResponse(agent, 'internal error');
  }

  if (result.decision === 'allow') return allowResponse(agent, null);

  if (agent === 'cursor') {
    return {
      decision: 'deny',
      exitCode: 0,
      output: JSON.stringify({
        permission: 'deny',
        userMessage: 'patient-zero blocked a suspicious package install. See agent message for details.',
        agentMessage: result.reason,
      }),
    };
  }

  return {
    decision: 'deny',
    exitCode: 0,
    output: JSON.stringify({
      hookSpecificOutput: {
        hookEventName: 'PreToolUse',
        permissionDecision: 'deny',
        permissionDecisionReason: result.reason,
      },
    }),
  };
}

function allowResponse(agent) {
  if (agent === 'cursor') {
    return { decision: 'allow', exitCode: 0, output: JSON.stringify({ permission: 'allow' }) };
  }
  return {
    decision: 'allow',
    exitCode: 0,
    output: JSON.stringify({
      hookSpecificOutput: { hookEventName: 'PreToolUse', permissionDecision: 'allow' },
    }),
  };
}
