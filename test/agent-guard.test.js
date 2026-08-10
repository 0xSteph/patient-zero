import { test } from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { parseInstallCommands, evaluateCommand, runGuard } from '../src/agent-guard.js';

const HERE = path.dirname(fileURLToPath(import.meta.url));
process.env.PATIENT_ZERO_IOCS_PATH = path.join(HERE, 'fixtures/iocs-test.json');

// A fetch stub that answers registry lookups with controllable metadata.
function fakeFetch(routes) {
  return async (url) => {
    for (const [needle, body] of Object.entries(routes)) {
      if (url.includes(needle)) {
        if (body === 404) return { status: 404, ok: false };
        return { status: 200, ok: true, json: async () => body };
      }
    }
    return { status: 404, ok: false };
  };
}

function npmDoc({ createdDaysAgo = 400, latestHoursAgo = 400 * 24, version = '2.0.0', scripts = {} } = {}) {
  const created = new Date(Date.now() - createdDaysAgo * 864e5).toISOString();
  const latestAt = new Date(Date.now() - latestHoursAgo * 36e5).toISOString();
  return {
    'dist-tags': { latest: version },
    time: { created, modified: latestAt, '1.0.0': created, [version]: latestAt },
    versions: { '1.0.0': { version: '1.0.0', scripts: {} }, [version]: { version, scripts } },
  };
}

// ---------- parseInstallCommands ----------

test('parse: plain npm install with packages', () => {
  const ops = parseInstallCommands('npm install chalk@4.0.0 lodash --save-dev');
  assert.equal(ops.length, 1);
  assert.equal(ops[0].ecosystem, 'npm');
  assert.deepEqual(ops[0].packages, [
    { name: 'chalk', spec: '4.0.0' },
    { name: 'lodash', spec: null },
  ]);
});

test('parse: scoped package with range', () => {
  const ops = parseInstallCommands('npm i @scope/pkg@^1.2.3');
  assert.deepEqual(ops[0].packages, [{ name: '@scope/pkg', spec: '^1.2.3' }]);
});

test('parse: chained commands find installs in every segment', () => {
  const ops = parseInstallCommands('cd app && pnpm add leftpad ; echo done && pip install requests==2.31.0');
  assert.equal(ops.length, 2);
  assert.equal(ops[0].pm, 'pnpm');
  assert.equal(ops[1].ecosystem, 'pypi');
  assert.deepEqual(ops[1].packages, [{ name: 'requests', spec: '==2.31.0' }]);
});

test('parse: npx and dlx pick up the executed package', () => {
  assert.deepEqual(parseInstallCommands('npx some-tool --flag')[0].packages, [{ name: 'some-tool', spec: null }]);
  assert.deepEqual(parseInstallCommands('pnpm dlx create-thing')[0].packages, [{ name: 'create-thing', spec: null }]);
  assert.deepEqual(parseInstallCommands('bunx cowsay hello')[0].packages, [{ name: 'cowsay', spec: null }]);
});

test('parse: uv / poetry / pipx map to pypi', () => {
  assert.equal(parseInstallCommands('uv add httpx')[0].ecosystem, 'pypi');
  assert.equal(parseInstallCommands('uv pip install flask')[0].ecosystem, 'pypi');
  assert.equal(parseInstallCommands('poetry add "pydantic[email]"')[0].packages[0].name, 'pydantic');
  assert.equal(parseInstallCommands('pipx install black')[0].ecosystem, 'pypi');
});

test('parse: bare installs are flagged bare, not package ops', () => {
  assert.equal(parseInstallCommands('npm ci')[0].bare, true);
  assert.equal(parseInstallCommands('yarn install')[0].bare, true);
  assert.equal(parseInstallCommands('pip install -r requirements.txt')[0].bare, true);
});

test('parse: non-install commands produce no ops', () => {
  assert.equal(parseInstallCommands('git status && npm test').length, 0);
  assert.equal(parseInstallCommands('npm run build').length, 0);
  assert.equal(parseInstallCommands('ls -la').length, 0);
  assert.equal(parseInstallCommands('echo "npm install chalk"').length, 0);
});

test('parse: local paths and URLs are not treated as registry packages', () => {
  const ops = parseInstallCommands('npm install ./local-dir https://example.com/x.tgz');
  assert.equal(ops[0].packages.length, 0);
});

// ---------- evaluateCommand ----------

test('evaluate: benign command allows without loading anything', async () => {
  const r = await evaluateCommand('git commit -m "hi"', { offline: true });
  assert.equal(r.decision, 'allow');
});

test('evaluate: known IoC package denies with remediation in reason', async () => {
  // fixture iocs-test.json contains chalk@4.0.0 as a package indicator
  const r = await evaluateCommand('npm install chalk@4.0.0', { offline: true, noHeuristics: true });
  assert.equal(r.decision, 'deny');
  assert.match(r.reason, /chalk@4\.0\.0/);
  assert.match(r.reason, /blocked/i);
});

test('evaluate: clean package with old registry history allows', async () => {
  const r = await evaluateCommand('npm install someokpkg', {
    fetchFn: fakeFetch({ '/someokpkg': npmDoc() }),
  });
  assert.equal(r.decision, 'allow');
});

test('evaluate: nonexistent package denies as hallucination', async () => {
  const r = await evaluateCommand('npm install def-not-real-pkg-xyz', {
    fetchFn: fakeFetch({ '/def-not-real-pkg-xyz': 404 }),
  });
  assert.equal(r.decision, 'deny');
  assert.match(r.reason, /hallucinated/);
});

test('evaluate: fresh version inside cooldown denies and suggests previous stable', async () => {
  const r = await evaluateCommand('npm install shinynewpkg', {
    fetchFn: fakeFetch({ '/shinynewpkg': npmDoc({ latestHoursAgo: 2 }) }),
  });
  assert.equal(r.decision, 'deny');
  assert.match(r.reason, /cooldown|published/i);
  assert.match(r.reason, /shinynewpkg@1\.0\.0/);
});

test('evaluate: typosquat lookalike denies offline (no registry needed)', async () => {
  const r = await evaluateCommand('npm install lodahs', { offline: true });
  assert.equal(r.decision, 'deny');
  assert.match(r.reason, /lodash/);
});

test('evaluate: registry outage fails open', async () => {
  const r = await evaluateCommand('npm install someokpkg', {
    fetchFn: async () => { throw new Error('network down'); },
  });
  assert.equal(r.decision, 'allow');
});

// ---------- runGuard (payload dialects) ----------

test('runGuard: claude-code payload → deny JSON with permissionDecision', async () => {
  const payload = JSON.stringify({
    tool_name: 'Bash',
    tool_input: { command: 'npm install chalk@4.0.0' },
  });
  const r = await runGuard('claude-code', payload, { offline: true, noHeuristics: true });
  assert.equal(r.decision, 'deny');
  const out = JSON.parse(r.output);
  assert.equal(out.hookSpecificOutput.permissionDecision, 'deny');
  assert.match(out.hookSpecificOutput.permissionDecisionReason, /chalk/);
});

test('runGuard: claude-code non-Bash tool allows immediately', async () => {
  const payload = JSON.stringify({ tool_name: 'Read', tool_input: { file_path: '/x' } });
  const r = await runGuard('claude-code', payload, { offline: true });
  assert.equal(r.decision, 'allow');
});

test('runGuard: cursor payload → deny JSON with permission field', async () => {
  const payload = JSON.stringify({ command: 'npm install chalk@4.0.0' });
  const r = await runGuard('cursor', payload, { offline: true, noHeuristics: true });
  const out = JSON.parse(r.output);
  assert.equal(out.permission, 'deny');
  assert.ok(out.agentMessage.length > 0);
});

test('runGuard: garbage stdin fails open', async () => {
  const r = await runGuard('claude-code', 'not json{{{', { offline: true });
  assert.equal(r.decision, 'allow');
});
