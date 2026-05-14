const GH_GRAPHQL_URL = 'https://api.github.com/graphql';
const FAMILY_KEY = 'ghsa-malware-imported';
const FAMILY_META = {
  display_name: 'GHSA-imported malware advisories',
  description:
    'Bulk-imported from GitHub Security Advisories with classification=MALWARE. Each indicator carries its own GHSA reference; we group them under one family because GHSA does not cluster reports into named campaigns.',
  first_observed: '2023-01-01',
  ecosystems: ['npm', 'pypi'],
  ioc_class_summary: 'package',
  primary_external_source: { name: 'GitHub Security Advisories', url: 'https://github.com/advisories' },
  active_threat: true,
  destructive_failsafe: false,
  references: ['https://github.com/advisories'],
};

const QUERY = `
  query Advisories($cursor: String) {
    securityAdvisories(first: 100, after: $cursor, classifications: MALWARE) {
      pageInfo { endCursor hasNextPage }
      nodes {
        ghsaId
        summary
        severity
        publishedAt
        updatedAt
        references { url }
        vulnerabilities(first: 50) {
          nodes {
            package { ecosystem name }
            vulnerableVersionRange
            firstPatchedVersion { identifier }
          }
        }
      }
    }
  }
`;

const ECOSYSTEM_MAP = {
  NPM: 'npm',
  PIP: 'pypi',
};

/**
 * Fetch malware-classified advisories from GitHub Security Advisories via GraphQL.
 * Requires a token (env GITHUB_TOKEN, or options.token).
 */
export async function fetchGithubAdvisories(options = {}) {
  const fetchFn = options.fetchFn ?? fetch;
  const token = options.token ?? process.env.GITHUB_TOKEN;
  const fetched_at = new Date().toISOString();

  if (!token && !options.fetchFn) {
    return {
      name: 'github-advisories',
      fetched_at,
      status: 'error',
      indicators: [],
      attack_families: {},
      error: 'no GITHUB_TOKEN available',
    };
  }

  const indicators = [];
  let cursor = null;
  let pages = 0;

  try {
    while (true) {
      const resp = await fetchFn(GH_GRAPHQL_URL, {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${token ?? 'test'}`,
          'Content-Type': 'application/json',
          'User-Agent': 'patient-zero-aggregator',
        },
        body: JSON.stringify({ query: QUERY, variables: { cursor } }),
      });
      if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
      const body = await resp.json();
      if (body.errors) throw new Error(body.errors.map((e) => e.message).join('; '));
      const conn = body?.data?.securityAdvisories;
      if (!conn) break;

      for (const advisory of conn.nodes ?? []) {
        indicators.push(...normalizeGhsaAdvisory(advisory));
      }

      pages += 1;
      if (!conn.pageInfo?.hasNextPage || pages > 100) break;
      cursor = conn.pageInfo.endCursor;
    }
  } catch (err) {
    return {
      name: 'github-advisories',
      fetched_at,
      status: indicators.length > 0 ? 'partial' : 'error',
      indicators,
      attack_families: indicators.length > 0 ? { [FAMILY_KEY]: FAMILY_META } : {},
      error: err.message,
    };
  }

  return {
    name: 'github-advisories',
    fetched_at,
    status: 'ok',
    indicators,
    attack_families: indicators.length > 0 ? { [FAMILY_KEY]: FAMILY_META } : {},
  };
}

function normalizeGhsaAdvisory(advisory) {
  const out = [];
  if (!advisory?.ghsaId) return out;
  const firstSeen = (advisory.publishedAt ?? '').slice(0, 10);
  const refs = Array.isArray(advisory.references)
    ? advisory.references.map((r) => r?.url).filter(Boolean)
    : [];
  const description = String(advisory.summary ?? `Malware advisory ${advisory.ghsaId}`).slice(0, 280);

  for (const vuln of advisory.vulnerabilities?.nodes ?? []) {
    const pkg = vuln.package;
    if (!pkg?.name) continue;
    const ecosystem = ECOSYSTEM_MAP[String(pkg.ecosystem).toUpperCase()];
    if (!ecosystem) continue;

    const range = vuln.vulnerableVersionRange ?? 'all';

    out.push({
      id: `${advisory.ghsaId}:${pkg.name}`,
      type: 'package',
      attack_family: FAMILY_KEY,
      severity: 'critical',
      first_seen: firstSeen || '2024-01-01',
      last_updated: (advisory.updatedAt ?? advisory.publishedAt ?? '').slice(0, 10) || firstSeen || '2024-01-01',
      source: 'github-advisories',
      description,
      references: refs.length > 0 ? refs : [`https://github.com/advisories/${advisory.ghsaId}`],
      ecosystem,
      name: pkg.name,
      versions: range,
      version_range: 'semver',
      advisory_id: advisory.ghsaId,
      remediation: {
        what_to_do: [
          `${pkg.name} ${range} is flagged as malware by GHSA ${advisory.ghsaId}.`,
          `Remove or pin away from this range and rotate credentials exposed to the install environment.`,
        ],
        commands: ecosystem === 'pypi' ? [`pip show ${pkg.name}`] : [`npm ls ${pkg.name}`],
      },
    });
  }

  return out;
}
