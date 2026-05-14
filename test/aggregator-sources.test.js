import { test } from 'node:test';
import assert from 'node:assert/strict';
import { zipSync, strToU8 } from 'fflate';
import { fetchOsv } from '../aggregator/sources/osv.js';
import { fetchGithubAdvisories } from '../aggregator/sources/github-advisories.js';

// ---------- OSV ----------

function buildOsvZip(advisories) {
  const files = {};
  for (const a of advisories) {
    files[`${a.id}.json`] = strToU8(JSON.stringify(a));
  }
  return zipSync(files);
}

test('osv: extracts MAL-* advisories and skips non-MAL ones', async () => {
  const mal = {
    id: 'MAL-2025-1234',
    published: '2025-09-08T00:00:00Z',
    summary: 'Malicious npm package: evilpkg',
    references: [{ type: 'ADVISORY', url: 'https://osv.dev/vulnerability/MAL-2025-1234' }],
    affected: [
      {
        package: { ecosystem: 'npm', name: 'evilpkg' },
        versions: ['1.0.0'],
      },
    ],
  };
  const benign = {
    id: 'GHSA-aaaa-bbbb-cccc',
    summary: 'Regular vuln, not malware',
    affected: [{ package: { ecosystem: 'npm', name: 'somepkg' }, versions: ['1.0.0'] }],
  };
  const zipBytes = buildOsvZip([mal, benign]);

  const result = await fetchOsv({
    sources: [{ ecosystem: 'npm', url: 'https://test/npm.zip' }],
    fetchFn: async () => ({
      ok: true,
      arrayBuffer: async () => zipBytes.buffer.slice(zipBytes.byteOffset, zipBytes.byteOffset + zipBytes.byteLength),
    }),
  });

  assert.equal(result.status, 'ok');
  assert.equal(result.indicators.length, 1);
  assert.equal(result.indicators[0].name, 'evilpkg');
  assert.equal(result.indicators[0].versions, '1.0.0');
  assert.equal(result.indicators[0].severity, 'critical');
  assert.ok(result.attack_families['osv-imported'], 'family should be present when indicators are returned');
  assert.equal(result.indicators[0].attack_family, 'osv-imported');
});

test('osv: required-field rule — generated indicators have remediation.what_to_do', async () => {
  const mal = {
    id: 'MAL-2026-5678',
    published: '2026-01-01T00:00:00Z',
    summary: 'Bad pkg',
    affected: [{ package: { ecosystem: 'PyPI', name: 'evilpypkg' }, versions: ['2.0.0'] }],
  };
  const zipBytes = buildOsvZip([mal]);
  const result = await fetchOsv({
    sources: [{ ecosystem: 'pypi', url: 'https://test/pypi.zip' }],
    fetchFn: async () => ({
      ok: true,
      arrayBuffer: async () => zipBytes.buffer.slice(zipBytes.byteOffset, zipBytes.byteOffset + zipBytes.byteLength),
    }),
  });
  assert.equal(result.indicators.length, 1);
  const ind = result.indicators[0];
  assert.ok(Array.isArray(ind.remediation?.what_to_do));
  assert.ok(ind.remediation.what_to_do.length >= 1);
  assert.equal(ind.ecosystem, 'pypi');
  assert.match(ind.remediation.commands[0], /pip show/);
});

test('osv: per-source error captured, partial status when other source succeeded', async () => {
  const okMal = {
    id: 'MAL-2025-1',
    published: '2025-01-01T00:00:00Z',
    summary: 'ok',
    affected: [{ package: { ecosystem: 'npm', name: 'a' }, versions: ['1.0.0'] }],
  };
  const okZip = buildOsvZip([okMal]);
  let call = 0;
  const result = await fetchOsv({
    sources: [
      { ecosystem: 'npm', url: 'https://test/npm.zip' },
      { ecosystem: 'pypi', url: 'https://test/pypi.zip' },
    ],
    fetchFn: async () => {
      call += 1;
      if (call === 1) {
        return { ok: true, arrayBuffer: async () => okZip.buffer.slice(okZip.byteOffset, okZip.byteOffset + okZip.byteLength) };
      }
      throw new Error('simulated pypi failure');
    },
  });
  assert.equal(result.status, 'partial');
  assert.equal(result.indicators.length, 1);
  assert.match(result.error, /pypi.*simulated/);
});

// ---------- GHSA ----------

function mockGhsaResponse(advisories, hasNext = false) {
  return {
    ok: true,
    json: async () => ({
      data: {
        securityAdvisories: {
          pageInfo: { endCursor: 'cursor1', hasNextPage: hasNext },
          nodes: advisories,
        },
      },
    }),
  };
}

test('ghsa: extracts malware advisories and normalizes per package', async () => {
  const advisory = {
    ghsaId: 'GHSA-1234-5678-90ab',
    summary: 'Malware: badpkg postinstall exfiltrates secrets',
    severity: 'CRITICAL',
    publishedAt: '2025-09-10T00:00:00Z',
    updatedAt: '2025-09-10T00:00:00Z',
    references: [{ url: 'https://github.com/advisories/GHSA-1234-5678-90ab' }],
    vulnerabilities: {
      nodes: [
        {
          package: { ecosystem: 'NPM', name: 'badpkg' },
          vulnerableVersionRange: '= 1.0.0',
          firstPatchedVersion: null,
        },
      ],
    },
  };
  const result = await fetchGithubAdvisories({
    token: 'fake-token',
    fetchFn: async () => mockGhsaResponse([advisory]),
  });
  assert.equal(result.status, 'ok');
  assert.equal(result.indicators.length, 1);
  assert.equal(result.indicators[0].name, 'badpkg');
  assert.equal(result.indicators[0].ecosystem, 'npm');
  assert.equal(result.indicators[0].versions, '= 1.0.0');
  assert.equal(result.indicators[0].severity, 'critical');
  assert.ok(result.attack_families['ghsa-malware-imported']);
  assert.ok(result.indicators[0].remediation?.what_to_do?.length >= 1);
});

test('ghsa: paginates through multiple pages', async () => {
  let page = 0;
  const fetchFn = async () => {
    page += 1;
    if (page === 1) return mockGhsaResponse([adv('GHSA-a')], true);
    if (page === 2) return mockGhsaResponse([adv('GHSA-b')], true);
    if (page === 3) return mockGhsaResponse([adv('GHSA-c')], false);
    throw new Error('too many pages');
  };
  const result = await fetchGithubAdvisories({ token: 'x', fetchFn });
  assert.equal(result.status, 'ok');
  assert.equal(result.indicators.length, 3);
  assert.equal(page, 3);
});

test('ghsa: missing token without injected fetchFn returns error status', async () => {
  const prev = process.env.GITHUB_TOKEN;
  delete process.env.GITHUB_TOKEN;
  try {
    const result = await fetchGithubAdvisories();
    assert.equal(result.status, 'error');
    assert.match(result.error, /GITHUB_TOKEN/);
    assert.equal(result.indicators.length, 0);
  } finally {
    if (prev !== undefined) process.env.GITHUB_TOKEN = prev;
  }
});

test('ghsa: GraphQL errors captured, not thrown', async () => {
  const result = await fetchGithubAdvisories({
    token: 'x',
    fetchFn: async () => ({ ok: true, json: async () => ({ errors: [{ message: 'rate limit exceeded' }] }) }),
  });
  assert.equal(result.status, 'error');
  assert.match(result.error, /rate limit/);
});

function adv(id) {
  return {
    ghsaId: id,
    summary: 'test',
    publishedAt: '2025-01-01T00:00:00Z',
    references: [],
    vulnerabilities: { nodes: [{ package: { ecosystem: 'NPM', name: `pkg-${id}` }, vulnerableVersionRange: '< 1.0.0' }] },
  };
}
