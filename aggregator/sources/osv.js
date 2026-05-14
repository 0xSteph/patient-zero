import { unzipSync } from 'fflate';

const OSV_NPM_URL = 'https://osv-vulnerabilities.storage.googleapis.com/npm/all.zip';
const OSV_PYPI_URL = 'https://osv-vulnerabilities.storage.googleapis.com/PyPI/all.zip';

const SOURCES = [
  { ecosystem: 'npm', url: OSV_NPM_URL },
  { ecosystem: 'pypi', url: OSV_PYPI_URL },
];

const FAMILY_KEY = 'osv-imported';
const FAMILY_META = {
  display_name: 'OSV-imported malicious packages',
  description:
    'Bulk-imported from OSV.dev malicious-package advisories (MAL-* IDs). Each indicator carries its own primary reference; we group them under one family because OSV does not cluster reports into named campaigns.',
  first_observed: '2024-01-01',
  ecosystems: ['npm', 'pypi'],
  ioc_class_summary: 'package',
  primary_external_source: { name: 'OSV.dev', url: 'https://osv.dev/list' },
  active_threat: true,
  destructive_failsafe: false,
  references: ['https://osv.dev/list'],
};

/**
 * Fetch malicious-package advisories from OSV.dev bulk dumps.
 * Filters to entries whose id starts with "MAL-" (OSV's malicious-package convention).
 *
 * @param {{ fetchFn?: typeof fetch, sources?: Array<{ecosystem: string, url: string}> }} [options]
 */
export async function fetchOsv(options = {}) {
  const fetchFn = options.fetchFn ?? fetch;
  const sources = options.sources ?? SOURCES;
  const fetched_at = new Date().toISOString();

  const indicators = [];
  const errors = [];

  for (const { ecosystem, url } of sources) {
    try {
      const resp = await fetchFn(url);
      if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
      const arr = new Uint8Array(await resp.arrayBuffer());
      const entries = unzipSync(arr);

      for (const [name, bytes] of Object.entries(entries)) {
        if (!name.endsWith('.json')) continue;
        let advisory;
        try {
          advisory = JSON.parse(new TextDecoder().decode(bytes));
        } catch {
          continue;
        }
        if (typeof advisory?.id !== 'string' || !advisory.id.startsWith('MAL-')) continue;
        indicators.push(...normalizeOsvAdvisory(advisory, ecosystem));
      }
    } catch (err) {
      errors.push(`${ecosystem}: ${err.message}`);
    }
  }

  const status = errors.length === 0 ? 'ok' : indicators.length > 0 ? 'partial' : 'error';

  return {
    name: 'osv',
    fetched_at,
    status,
    indicators,
    attack_families: indicators.length > 0 ? { [FAMILY_KEY]: FAMILY_META } : {},
    ...(errors.length > 0 ? { error: errors.join('; ') } : {}),
  };
}

function normalizeOsvAdvisory(advisory, ecosystem) {
  const out = [];
  const firstSeen = (advisory.published ?? advisory.modified ?? '').slice(0, 10);
  const refs = Array.isArray(advisory.references)
    ? advisory.references.map((r) => r?.url).filter(Boolean)
    : [];
  const description = String(advisory.summary ?? advisory.details ?? `Malicious package advisory ${advisory.id}`).slice(0, 280);

  for (const affected of advisory.affected ?? []) {
    const pkg = affected.package;
    if (!pkg?.name) continue;
    if (pkg.ecosystem && pkg.ecosystem.toLowerCase() !== ecosystem.toLowerCase() && pkg.ecosystem.toLowerCase() !== ecosystemOsvName(ecosystem)) {
      continue;
    }
    const versionsArr = Array.isArray(affected.versions) ? affected.versions : [];
    // OSV may also have ranges. For v0.1 we prefer explicit versions when present;
    // when absent we mark as "all" so the matcher can decide.
    const versionsStr = versionsArr.length > 0 ? versionsArr.join('||') : 'all';

    out.push({
      id: `${advisory.id}:${pkg.name}`,
      type: 'package',
      attack_family: FAMILY_KEY,
      severity: 'critical',
      first_seen: firstSeen || '2024-01-01',
      last_updated: (advisory.modified ?? advisory.published ?? '').slice(0, 10) || firstSeen || '2024-01-01',
      source: ecosystem === 'pypi' ? 'osv-pypi' : 'osv-npm',
      description,
      references: refs,
      ecosystem,
      name: pkg.name,
      versions: versionsStr,
      version_range: versionsArr.length === 1 ? 'exact' : versionsArr.length > 1 ? 'list' : 'all',
      advisory_id: advisory.id,
      remediation: {
        what_to_do: [
          `${pkg.name} version ${versionsStr} is on OSV's malicious-package list.`,
          `Remove this package from your lockfile and pin to a non-listed version after reviewing the advisory.`,
          `Rotate any credentials that were exposed to the install environment during the install window.`,
        ],
        commands: ecosystem === 'pypi' ? [`pip show ${pkg.name}`] : [`npm ls ${pkg.name}`],
      },
    });
  }

  return out;
}

function ecosystemOsvName(ecosystem) {
  // OSV uses canonical-cased names: "npm", "PyPI"
  return ecosystem === 'pypi' ? 'pypi' : ecosystem.toLowerCase();
}
