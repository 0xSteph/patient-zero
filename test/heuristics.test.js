import { test } from 'node:test';
import assert from 'node:assert/strict';
import { parsePackageSpec, levenshtein, checkTyposquat, runHeuristics } from '../src/heuristics.js';

// ---------- parsePackageSpec ----------

test('parsePackageSpec: npm plain / pinned / scoped / ranged', () => {
  assert.deepEqual(parsePackageSpec('chalk', 'npm'), { name: 'chalk', spec: null });
  assert.deepEqual(parsePackageSpec('chalk@4.0.0', 'npm'), { name: 'chalk', spec: '4.0.0' });
  assert.deepEqual(parsePackageSpec('@scope/pkg@^1.2.3', 'npm'), { name: '@scope/pkg', spec: '^1.2.3' });
  assert.deepEqual(parsePackageSpec('@scope/pkg', 'npm'), { name: '@scope/pkg', spec: null });
});

test('parsePackageSpec: pypi pins, extras, case folding', () => {
  assert.deepEqual(parsePackageSpec('requests==2.31.0', 'pypi'), { name: 'requests', spec: '==2.31.0' });
  assert.deepEqual(parsePackageSpec('uvicorn[standard]', 'pypi'), { name: 'uvicorn', spec: null });
  assert.deepEqual(parsePackageSpec('Django>=4.0', 'pypi'), { name: 'django', spec: '>=4.0' });
});

// ---------- levenshtein (OSA) ----------

test('levenshtein: substitution, insertion, transposition each count once', () => {
  assert.equal(levenshtein('chalk', 'chalk'), 0);
  assert.equal(levenshtein('chalk', 'chalx'), 1);
  assert.equal(levenshtein('chalk', 'chaalk'), 1);
  assert.equal(levenshtein('lodash', 'lodahs'), 1); // transposition
  assert.equal(levenshtein('react', 'vue', 2), 3);  // early-bail returns max+1
});

// ---------- checkTyposquat ----------

test('checkTyposquat: popular names themselves are fine', async () => {
  assert.equal((await checkTyposquat('lodash', 'npm')).suspicious, false);
  assert.equal((await checkTyposquat('react-dom', 'npm')).suspicious, false);
  assert.equal((await checkTyposquat('requests', 'pypi')).suspicious, false);
});

test('checkTyposquat: one-edit lookalikes and affix squats are flagged', async () => {
  const squat = await checkTyposquat('lodahs', 'npm');
  assert.equal(squat.suspicious, true);
  assert.equal(squat.lookalikeOf, 'lodash');

  const affix = await checkTyposquat('expressjs', 'npm');
  assert.equal(affix.suspicious, true);
  assert.equal(affix.lookalikeOf, 'express');

  const nodeAffix = await checkTyposquat('node-lodash', 'npm');
  assert.equal(nodeAffix.suspicious, true);
});

test('checkTyposquat: unrelated names pass', async () => {
  assert.equal((await checkTyposquat('my-cool-internal-lib', 'npm')).suspicious, false);
});

// ---------- runHeuristics ----------

function fakeFetch(handler) {
  return async (url) => handler(url);
}

test('runHeuristics: offline mode does typosquat only, marks network skipped', async () => {
  const r = await runHeuristics([{ name: 'lodahs', spec: null }], 'npm', { offline: true });
  assert.equal(r.networkSkipped, true);
  assert.equal(r.findings.length, 1);
  assert.equal(r.findings[0].rule, 'typosquat-lookalike');
});

test('runHeuristics: 404 registry response → nonexistent-package finding', async () => {
  const r = await runHeuristics([{ name: 'ghost-pkg', spec: null }], 'npm', {
    fetchFn: fakeFetch(async () => ({ status: 404, ok: false })),
  });
  assert.equal(r.findings[0].rule, 'nonexistent-package');
  assert.equal(r.findings[0].severity, 'high');
});

test('runHeuristics: brand-new package and cooldown both derive from time map', async () => {
  const now = Date.now();
  const doc = {
    'dist-tags': { latest: '1.0.1' },
    time: {
      created: new Date(now - 2 * 864e5).toISOString(),
      '1.0.0': new Date(now - 2 * 864e5).toISOString(),
      '1.0.1': new Date(now - 3600e3).toISOString(),
    },
    versions: { '1.0.0': { version: '1.0.0' }, '1.0.1': { version: '1.0.1' } },
  };
  const r = await runHeuristics([{ name: 'fresh-pkg', spec: null }], 'npm', {
    fetchFn: fakeFetch(async () => ({ status: 200, ok: true, json: async () => doc })),
  });
  const rules = r.findings.map((f) => f.rule);
  assert.ok(rules.includes('brand-new-package'));
  // brand-new suppresses the redundant cooldown finding
  assert.ok(!rules.includes('cooldown-violation'));
});

test('runHeuristics: cooldown finding suggests previous stable version', async () => {
  const now = Date.now();
  const doc = {
    'dist-tags': { latest: '2.0.0' },
    time: {
      created: new Date(now - 400 * 864e5).toISOString(),
      '1.9.0': new Date(now - 30 * 864e5).toISOString(),
      '2.0.0': new Date(now - 2 * 3600e3).toISOString(),
    },
    versions: { '1.9.0': { version: '1.9.0' }, '2.0.0': { version: '2.0.0' } },
  };
  const r = await runHeuristics([{ name: 'estab-pkg', spec: null }], 'npm', {
    fetchFn: fakeFetch(async () => ({ status: 200, ok: true, json: async () => doc })),
  });
  const cooldown = r.findings.find((f) => f.rule === 'cooldown-violation');
  assert.ok(cooldown);
  assert.equal(cooldown.previousStableVersion, '1.9.0');
  assert.match(cooldown.suggestion, /estab-pkg@1\.9\.0/);
});

test('runHeuristics: old stable package with install scripts → info only', async () => {
  const now = Date.now();
  const doc = {
    'dist-tags': { latest: '3.0.0' },
    time: {
      created: new Date(now - 900 * 864e5).toISOString(),
      '3.0.0': new Date(now - 200 * 864e5).toISOString(),
    },
    versions: { '3.0.0': { version: '3.0.0', scripts: { postinstall: 'node setup.js' } } },
  };
  const r = await runHeuristics([{ name: 'native-pkg', spec: null }], 'npm', {
    fetchFn: fakeFetch(async () => ({ status: 200, ok: true, json: async () => doc })),
  });
  assert.deepEqual(r.findings.map((f) => f.rule), ['install-scripts']);
  assert.equal(r.findings[0].severity, 'info');
});

test('runHeuristics: pypi 404 → nonexistent, pypi fresh release → cooldown', async () => {
  const missing = await runHeuristics([{ name: 'no-such-dist', spec: null }], 'pypi', {
    fetchFn: fakeFetch(async () => ({ status: 404, ok: false })),
  });
  assert.equal(missing.findings[0].rule, 'nonexistent-package');

  const now = Date.now();
  const doc = {
    info: { version: '2.0.0' },
    releases: {
      '1.0.0': [{ upload_time_iso_8601: new Date(now - 500 * 864e5).toISOString() }],
      '2.0.0': [{ upload_time_iso_8601: new Date(now - 3600e3).toISOString() }],
    },
  };
  const fresh = await runHeuristics([{ name: 'somepydist', spec: null }], 'pypi', {
    fetchFn: fakeFetch(async () => ({ status: 200, ok: true, json: async () => doc })),
  });
  const cooldown = fresh.findings.find((f) => f.rule === 'cooldown-violation');
  assert.ok(cooldown);
  assert.equal(cooldown.previousStableVersion, '1.0.0');
});

test('runHeuristics: network failure fails open with networkSkipped flag', async () => {
  const r = await runHeuristics([{ name: 'whatever-pkg', spec: null }], 'npm', {
    fetchFn: fakeFetch(async () => { throw new Error('boom'); }),
  });
  assert.equal(r.findings.length, 0);
  assert.equal(r.networkSkipped, true);
});
