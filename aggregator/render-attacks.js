/**
 * Render docs/ATTACKS.md from a normalized iocs.json document.
 * Produces the public-facing trust-table that the README references.
 *
 * @param {Object} doc — output of normalize.merge() + top-level metadata
 * @returns {string} markdown
 */
export function renderAttacks(doc) {
  const lines = [];
  lines.push('# Tracked attacks');
  lines.push('');
  lines.push(
    'Auto-generated from [`data/iocs.json`](../data/iocs.json) by the [aggregator](../aggregator/). ' +
      'To add an attack family, see [docs/CONTRIBUTING.md](CONTRIBUTING.md). Every row must cite a `primary_external_source`.',
  );
  lines.push('');
  lines.push(
    `**Coverage window:** ${doc.coverage_window.start ?? '—'} → ${doc.coverage_window.end ?? '—'}  ` +
      `· **Families tracked:** ${doc.attack_family_count}  ` +
      `· **Indicators:** ${doc.indicator_count}  ` +
      `· **Last updated:** ${doc.generated_at}`,
  );
  lines.push('');
  lines.push('| Attack family | First observed | Ecosystem | IoC class | Active threat | Source |');
  lines.push('|---|---|---|---|---|---|');

  const entries = Object.entries(doc.attack_families).sort(
    ([, a], [, b]) => (b.first_observed ?? '').localeCompare(a.first_observed ?? ''),
  );

  for (const [, fam] of entries) {
    const eco = (fam.ecosystems ?? []).join(', ');
    const ioc = fam.ioc_class_summary ?? '—';
    const active = fam.active_threat ? 'yes' : 'no';
    const src = fam.primary_external_source
      ? `[${fam.primary_external_source.name}](${fam.primary_external_source.url})`
      : '—';
    lines.push(
      `| ${fam.display_name} | ${fam.first_observed} | ${eco} | ${ioc} | ${active} | ${src} |`,
    );
  }

  lines.push('');
  lines.push('---');
  lines.push('');
  lines.push(
    '> If `Active threat: yes` shows for a family, IoCs in that family represent campaigns still seen in the wild. ' +
      '`Active threat: no` families are tracked for forensic completeness; finding one of those on your machine ' +
      'still means you were affected and credentials may be exposed.',
  );
  lines.push('');

  return lines.join('\n');
}
