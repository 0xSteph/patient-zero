/**
 * Live OSV.dev malware lookup.
 *
 * The aggregated IoC database ships a rolling window of recent malicious
 * packages; the full corpus (220k+ MAL entries for npm alone) is far too big
 * to bundle. This module closes the gap at the moment it matters — install
 * time — by querying api.osv.dev for the exact packages about to be
 * installed. Only MAL-* advisories (the OpenSSF malicious-packages feed)
 * count: ordinary CVEs in a legit package must never block an install.
 *
 * Fail-open by contract: any network or parse error returns zero findings.
 */

const OSV_API = 'https://api.osv.dev/v1';
const FETCH_TIMEOUT_MS = 6000;
const MAX_DETAIL_LOOKUPS = 5;

const OSV_ECOSYSTEM = { npm: 'npm', pypi: 'PyPI' };

/**
 * Check packages against OSV's malicious-package advisories.
 *
 * Entries with an exact `version` get a precise verdict. Entries without one
 * are only flagged when the advisory marks the *entire package* malicious
 * (introduced: 0, never fixed) — a version-specific compromise of a legit
 * package (e.g. a hijacked release that was later unpublished) must not
 * block an unpinned install that would resolve to a clean latest.
 *
 * @param {Array<{name: string, version?: string|null, ecosystem: 'npm'|'pypi'}>} entries
 * @param {{ fetchFn?: typeof fetch }} [options]
 * @returns {Promise<Array<{rule: 'osv-malware', severity: 'critical', name: string, version: string|null, osvIds: string[], message: string, suggestion: string}>>}
 */
export async function checkOsvMalware(entries, options = {}) {
  const fetchFn = options.fetchFn ?? fetch;
  const queryable = entries.filter((e) => OSV_ECOSYSTEM[e.ecosystem]);
  if (queryable.length === 0) return [];

  let results;
  try {
    const resp = await fetchFn(`${OSV_API}/querybatch`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        queries: queryable.map((e) => ({
          package: { name: e.name, ecosystem: OSV_ECOSYSTEM[e.ecosystem] },
          ...(e.version ? { version: e.version } : {}),
        })),
      }),
      signal: AbortSignal.timeout(FETCH_TIMEOUT_MS),
    });
    if (!resp.ok) return [];
    ({ results } = await resp.json());
  } catch {
    return [];
  }
  if (!Array.isArray(results)) return [];

  const findings = [];
  let detailLookups = 0;

  for (let i = 0; i < queryable.length; i++) {
    const entry = queryable[i];
    const malIds = (results[i]?.vulns ?? [])
      .map((v) => v.id)
      .filter((id) => typeof id === 'string' && id.startsWith('MAL-'));
    if (malIds.length === 0) continue;

    if (entry.version) {
      findings.push(buildFinding(entry, malIds));
      continue;
    }

    // Unpinned install: confirm the whole package is malicious before flagging.
    let wholePackage = false;
    for (const id of malIds.slice(0, MAX_DETAIL_LOOKUPS)) {
      if (detailLookups >= MAX_DETAIL_LOOKUPS) break;
      detailLookups++;
      if (await advisoryCoversAllVersions(id, entry, fetchFn)) {
        wholePackage = true;
        break;
      }
    }
    if (wholePackage) findings.push(buildFinding(entry, malIds));
  }

  return findings;
}

function buildFinding(entry, osvIds) {
  const at = entry.version ? `${entry.name}@${entry.version}` : entry.name;
  return {
    rule: 'osv-malware',
    severity: 'critical',
    name: entry.name,
    version: entry.version ?? null,
    osvIds,
    message: `${at} is flagged as malicious by OSV.dev (${osvIds.slice(0, 3).join(', ')}${osvIds.length > 3 ? ', …' : ''}) — the OpenSSF malicious-packages feed.`,
    suggestion: `Do not install. Details: https://osv.dev/vulnerability/${osvIds[0]}`,
  };
}

async function advisoryCoversAllVersions(osvId, entry, fetchFn) {
  try {
    const resp = await fetchFn(`${OSV_API}/vulns/${encodeURIComponent(osvId)}`, {
      signal: AbortSignal.timeout(FETCH_TIMEOUT_MS),
    });
    if (!resp.ok) return false;
    const vuln = await resp.json();
    for (const aff of vuln.affected ?? []) {
      if (aff.package?.name?.toLowerCase() !== entry.name.toLowerCase()) continue;
      for (const range of aff.ranges ?? []) {
        const events = range.events ?? [];
        const introducedZero = events.some((e) => e.introduced === '0');
        const hasEnd = events.some((e) => e.fixed !== undefined || e.last_affected !== undefined);
        if (introducedZero && !hasEnd) return true;
      }
    }
    return false;
  } catch {
    return false;
  }
}
