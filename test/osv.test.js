import { test } from 'node:test';
import assert from 'node:assert/strict';
import { zipSync, strToU8 } from 'fflate';
import { checkOsvMalware } from '../src/osv.js';
import { fetchOsvMalware, vulnToIndicators } from '../aggregator/sources/osv-malware.js';

// ---------- checkOsvMalware (live lookup, stubbed fetch) ----------

function osvFetch({ batchResults, vulnDetails = {} }) {
  return async (url, init) => {
    if (url.endsWith('/querybatch')) {
      const { queries } = JSON.parse(init.body);
      return { ok: true, json: async () => ({ results: batchResults(queries) }) };
    }
    const id = decodeURIComponent(url.split('/').pop());
    if (vulnDetails[id]) return { ok: true, json: async () => vulnDetails[id] };
    return { ok: false, status: 404 };
  };
}

test('checkOsvMalware: pinned version with MAL hit → critical finding', async () => {
  const findings = await checkOsvMalware(
    [{ name: 'evil-pkg', version: '1.0.0', ecosystem: 'npm' }],
    {
      fetchFn: osvFetch({
        batchResults: () => [{ vulns: [{ id: 'MAL-2026-123' }, { id: 'GHSA-not-malware' }] }],
      }),
    },
  );
  assert.equal(findings.length, 1);
  assert.equal(findings[0].severity, 'critical');
  assert.deepEqual(findings[0].osvIds, ['MAL-2026-123']);
  assert.match(findings[0].suggestion, /osv\.dev\/vulnerability\/MAL-2026-123/);
});

test('checkOsvMalware: non-MAL advisories (plain CVEs) never block', async () => {
  const findings = await checkOsvMalware(
    [{ name: 'lodash', version: '4.17.20', ecosystem: 'npm' }],
    { fetchFn: osvFetch({ batchResults: () => [{ vulns: [{ id: 'GHSA-xxxx-yyyy' }] }] }) },
  );
  assert.equal(findings.length, 0);
});

test('checkOsvMalware: unpinned + whole-package-malicious → finding', async () => {
  const findings = await checkOsvMalware(
    [{ name: 'squat-pkg', version: null, ecosystem: 'npm' }],
    {
      fetchFn: osvFetch({
        batchResults: () => [{ vulns: [{ id: 'MAL-2026-1' }] }],
        vulnDetails: {
          'MAL-2026-1': {
            affected: [{
              package: { name: 'squat-pkg' },
              ranges: [{ type: 'SEMVER', events: [{ introduced: '0' }] }],
            }],
          },
        },
      }),
    },
  );
  assert.equal(findings.length, 1);
});

test('checkOsvMalware: unpinned + version-specific compromise → no finding', async () => {
  // A hijacked release of a legit package (later fixed) must not block
  // an unpinned install that resolves to a clean latest.
  const findings = await checkOsvMalware(
    [{ name: 'debug', version: null, ecosystem: 'npm' }],
    {
      fetchFn: osvFetch({
        batchResults: () => [{ vulns: [{ id: 'MAL-2025-9' }] }],
        vulnDetails: {
          'MAL-2025-9': {
            affected: [{
              package: { name: 'debug' },
              ranges: [{ type: 'SEMVER', events: [{ introduced: '4.4.2' }, { fixed: '4.4.3' }] }],
            }],
          },
        },
      }),
    },
  );
  assert.equal(findings.length, 0);
});

test('checkOsvMalware: pypi maps to the PyPI ecosystem name', async () => {
  let captured;
  await checkOsvMalware(
    [{ name: 'evil-dist', version: '0.1', ecosystem: 'pypi' }],
    {
      fetchFn: osvFetch({
        batchResults: (queries) => {
          captured = queries;
          return [{ vulns: [] }];
        },
      }),
    },
  );
  assert.equal(captured[0].package.ecosystem, 'PyPI');
});

test('checkOsvMalware: network failure fails open', async () => {
  const findings = await checkOsvMalware(
    [{ name: 'x', version: '1.0.0', ecosystem: 'npm' }],
    { fetchFn: async () => { throw new Error('down'); } },
  );
  assert.deepEqual(findings, []);
});

// ---------- vulnToIndicators (aggregator mapping) ----------

test('vulnToIndicators: explicit version list → version_range list', () => {
  const inds = vulnToIndicators({
    id: 'MAL-2026-42',
    published: '2026-08-01T00:00:00Z',
    modified: '2026-08-02T00:00:00Z',
    summary: 'Malicious code in foo (npm)',
    affected: [{ package: { name: 'foo' }, versions: ['1.0.0', '1.0.1'] }],
  }, 'npm');
  assert.equal(inds.length, 1);
  assert.equal(inds[0].id, 'MAL-2026-42:npm:foo');
  assert.equal(inds[0].versions, '1.0.0||1.0.1');
  assert.equal(inds[0].version_range, 'list');
  assert.equal(inds[0].severity, 'critical');
  assert.equal(inds[0].first_seen, '2026-08-01');
  assert.ok(inds[0].remediation.what_to_do.length >= 1);
});

test('vulnToIndicators: introduced-0 range → match all versions (no versions field)', () => {
  const inds = vulnToIndicators({
    id: 'MAL-2026-43',
    published: '2026-08-01T00:00:00Z',
    affected: [{ package: { name: 'bar' }, ranges: [{ type: 'SEMVER', events: [{ introduced: '0' }] }] }],
  }, 'npm');
  assert.equal(inds[0].versions, undefined);
});

test('vulnToIndicators: bounded semver range → range clause', () => {
  const inds = vulnToIndicators({
    id: 'MAL-2026-44',
    published: '2026-08-01T00:00:00Z',
    affected: [{ package: { name: 'baz' }, ranges: [{ type: 'SEMVER', events: [{ introduced: '2.0.0' }, { fixed: '2.0.2' }] }] }],
  }, 'npm');
  assert.equal(inds[0].versions, '>=2.0.0 <2.0.2');
});

// ---------- fetchOsvMalware (zip ingestion) ----------

function makeZip(files) {
  return zipSync(Object.fromEntries(
    Object.entries(files).map(([name, obj]) => [name, strToU8(JSON.stringify(obj))]),
  ));
}

const NOW = Date.parse('2026-08-10T00:00:00Z');

function malEntry(id, name, publishedIso) {
  return {
    id,
    published: publishedIso,
    modified: publishedIso,
    summary: `Malicious code in ${name} (npm)`,
    affected: [{ package: { name }, ranges: [{ type: 'SEMVER', events: [{ introduced: '0' }] }] }],
  };
}

test('fetchOsvMalware: keeps recent MAL entries, drops old ones and non-MAL files', async () => {
  const zip = makeZip({
    'MAL-2026-100.json': malEntry('MAL-2026-100', 'fresh-evil', '2026-08-01T00:00:00Z'),
    'MAL-2026-101.json': malEntry('MAL-2026-101', 'stale-evil', '2026-02-01T00:00:00Z'),
    'GHSA-aaaa.json': malEntry('GHSA-aaaa', 'not-mal-prefixed', '2026-08-01T00:00:00Z'),
  });
  const result = await fetchOsvMalware({ now: NOW, windowDays: 30, fetchZip: async () => zip });
  assert.equal(result.status, 'ok');
  assert.deepEqual(result.indicators.map((i) => i.name).sort(), ['fresh-evil', 'fresh-evil']); // npm + pypi feeds both served the same zip
  assert.ok(result.attack_families['osv-malicious-packages']);
});

test('fetchOsvMalware: one feed failing is partial, both failing is error', async () => {
  const zip = makeZip({ 'MAL-2026-100.json': malEntry('MAL-2026-100', 'fresh-evil', '2026-08-01T00:00:00Z') });
  let call = 0;
  const partial = await fetchOsvMalware({
    now: NOW,
    windowDays: 30,
    fetchZip: async () => { if (call++ === 0) return zip; throw new Error('HTTP 500'); },
  });
  assert.equal(partial.status, 'ok');
  assert.match(partial.error, /partial/);
  assert.equal(partial.indicators.length, 1);

  const broken = await fetchOsvMalware({
    now: NOW,
    windowDays: 30,
    fetchZip: async () => { throw new Error('HTTP 500'); },
  });
  assert.equal(broken.status, 'error');
  assert.equal(broken.indicators.length, 0);
});
