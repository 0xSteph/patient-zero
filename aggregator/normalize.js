const INDICATOR_TYPES = ['package', 'file', 'process', 'github', 'network', 'mcp'];

/**
 * Merge results from multiple sources into the v1.0 grouped output shape.
 * Dedupes indicators by `id`. On conflict, later sources do NOT overwrite earlier ones
 * (manual is loaded first; OSV/GHSA may not overwrite manual entries by accident).
 *
 * @param {Array<{name: string, status: string, indicators: Array, attack_families: Object}>} sources
 * @returns {{
 *   attack_families: Object,
 *   indicators: Object,
 *   indexes: Object,
 *   coverage_window: {start: string, end: string},
 *   attack_family_count: number,
 *   indicator_count: number,
 *   sources: Array
 * }}
 */
export function merge(sources) {
  const attackFamilies = {};
  const indicators = Object.fromEntries(INDICATOR_TYPES.map((t) => [t, []]));
  const seenIds = new Set();

  for (const src of sources) {
    if (src.status !== 'ok') continue;

    for (const [key, fam] of Object.entries(src.attack_families ?? {})) {
      if (!attackFamilies[key]) attackFamilies[key] = fam;
    }

    for (const ind of src.indicators ?? []) {
      if (!ind || typeof ind !== 'object') continue;
      if (!ind.id || seenIds.has(ind.id)) continue;
      if (!INDICATOR_TYPES.includes(ind.type)) continue;
      seenIds.add(ind.id);
      indicators[ind.type].push(ind);
    }
  }

  const indexes = buildIndexes(indicators);
  const coverage_window = computeCoverageWindow(attackFamilies);
  const indicator_count = INDICATOR_TYPES.reduce((sum, t) => sum + indicators[t].length, 0);

  return {
    attack_families: attackFamilies,
    indicators,
    indexes,
    coverage_window,
    attack_family_count: Object.keys(attackFamilies).length,
    indicator_count,
    sources: sources.map((s) => ({
      name: s.name,
      fetched_at: s.fetched_at,
      indicator_count: (s.indicators ?? []).length,
      status: s.status,
      ...(s.error ? { error: s.error } : {}),
    })),
  };
}

function buildIndexes(indicators) {
  const packages_by_ecosystem_name = {};
  for (const pkg of indicators.package) {
    if (!pkg.ecosystem || !pkg.name) continue;
    const key = `${pkg.ecosystem.toLowerCase()}:${pkg.name.toLowerCase()}`;
    if (!packages_by_ecosystem_name[key]) packages_by_ecosystem_name[key] = [];
    packages_by_ecosystem_name[key].push(pkg.id);
  }
  return { packages_by_ecosystem_name };
}

function computeCoverageWindow(attackFamilies) {
  const dates = Object.values(attackFamilies)
    .map((f) => f.first_observed)
    .filter(Boolean)
    .sort();
  return {
    start: dates[0] ?? null,
    end: 'present',
  };
}
