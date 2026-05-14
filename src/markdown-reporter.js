/**
 * Render scan results as a Markdown report. Shape:
 *
 *   # patient-zero scan report
 *
 *   - **When:** ISO timestamp
 *   - **Duration:** Xs
 *   - **Coverage:** start → end
 *
 *   ## Critical: Destructive failsafe detected   ← only if applicable
 *
 *   ## Findings
 *   ### <attack family name>
 *   #### CRITICAL · <indicator id>
 *   - Artifact ...
 *   - What to do ...
 *
 *   ## Scanner summary
 *
 *   ## No findings  (alternative when 0 findings)
 */

const SEVERITY_ORDER = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };

export function renderMarkdown(args) {
  const { iocs, findings, scanned, errors, skipped, durationMs, iocSource, iocAgeMs } = args;
  const lines = [];

  lines.push('# patient-zero scan report');
  lines.push('');
  lines.push(`- **When:** ${new Date().toISOString()}`);
  lines.push(`- **Duration:** ${(durationMs / 1000).toFixed(2)}s`);
  lines.push(
    `- **Coverage window:** ${iocs.coverage_window?.start ?? '—'} → ${iocs.coverage_window?.end ?? '—'}`,
  );
  lines.push(
    `- **IoC database:** ${iocs.attack_family_count ?? '?'} families, ${iocs.indicator_count ?? '?'} indicators (${iocSource})`,
  );
  lines.push('');

  // Failsafe banner
  const failsafeFindings = findings.filter((f) => {
    const fam = iocs.attack_families?.[f.indicator.attack_family];
    return fam?.destructive_failsafe === true;
  });
  if (failsafeFindings.length > 0) {
    const families = new Set(
      failsafeFindings.map((f) => iocs.attack_families[f.indicator.attack_family].display_name),
    );
    lines.push('## ⚠️ Destructive failsafe detected');
    lines.push('');
    lines.push(`**${[...families].join(', ')}** has a known destructive failsafe.`);
    lines.push('');
    lines.push('**Do NOT revoke npm or GitHub tokens until the host is isolated.**');
    lines.push('Read [`docs/SHAI-HULUD-FAILSAFE.md`](docs/SHAI-HULUD-FAILSAFE.md) before any defensive action.');
    lines.push('');
  }

  if (findings.length === 0) {
    lines.push('## ✅ No known IoCs matched');
    lines.push('');
    lines.push(
      'patient-zero scanned this machine against every indicator in the database and found nothing. ' +
        'This means: at the time of scan, no known supply-chain attack family had a positive match here.',
    );
    lines.push('');
  } else {
    lines.push('## Findings');
    lines.push('');
    const byFamily = groupByFamily(findings);
    for (const [familyKey, group] of byFamily) {
      const fam = iocs.attack_families?.[familyKey];
      lines.push(`### ${fam?.display_name ?? familyKey}`);
      if (fam?.primary_external_source) {
        lines.push('');
        lines.push(`Source: [${fam.primary_external_source.name}](${fam.primary_external_source.url})`);
      }
      lines.push('');
      group.sort(
        (a, b) =>
          (SEVERITY_ORDER[a.indicator.severity] ?? 99) - (SEVERITY_ORDER[b.indicator.severity] ?? 99),
      );
      for (const finding of group) {
        lines.push(...renderFindingMd(finding));
      }
    }
  }

  lines.push('## Scanner summary');
  lines.push('');
  lines.push('| Scanner | Counted |');
  lines.push('|---|---|');
  if (scanned.lockfiles_found != null) lines.push(`| Lockfiles | ${scanned.lockfiles_found} |`);
  if (scanned.configs_found != null) lines.push(`| MCP configs | ${scanned.configs_found} |`);
  if (scanned.paths_checked != null) lines.push(`| Local paths | ${scanned.paths_checked} |`);
  if (scanned.processes_checked != null) lines.push(`| Processes | ${scanned.processes_checked} |`);
  if (scanned.repos_checked != null) lines.push(`| GitHub repos | ${scanned.repos_checked} |`);
  lines.push('');

  if (skipped?.length) {
    lines.push(`**Skipped:** ${skipped.join(', ')}`);
    lines.push('');
  }
  if (errors?.length) {
    lines.push('## Scanner errors');
    lines.push('');
    for (const e of errors) lines.push(`- ${e}`);
    lines.push('');
  }

  return lines.join('\n');
}

function renderFindingMd(finding) {
  const lines = [];
  const ind = finding.indicator;
  lines.push(`#### ${ind.severity.toUpperCase()} · \`${ind.id}\``);
  lines.push('');
  lines.push(`- **${labelForType(ind.type)}:** ${describeArtifact(finding)}`);
  if (ind.description) lines.push(`- **Description:** ${ind.description}`);
  if (ind.remediation?.what_to_do?.length) {
    lines.push('- **What to do:**');
    for (const step of ind.remediation.what_to_do) lines.push(`  - ${step}`);
  }
  if (ind.remediation?.commands?.length) {
    lines.push('- **Commands:**');
    lines.push('');
    lines.push('  ```sh');
    for (const cmd of ind.remediation.commands) lines.push(`  ${cmd}`);
    lines.push('  ```');
  }
  if (ind.references?.length) {
    lines.push(`- **References:** ${ind.references.map((u) => `<${u}>`).join(', ')}`);
  }
  lines.push('');
  return lines;
}

function labelForType(t) {
  return { package: 'Package', file: 'File', process: 'Process', github: 'Repo', network: 'Network', mcp: 'MCP server' }[t] ?? 'Artifact';
}

function describeArtifact(finding) {
  const a = finding.artifact;
  switch (finding.indicator.type) {
    case 'package':
      return `\`${a.name}@${a.version}\` in \`${a.lockfile}\``;
    case 'file':
      return `\`${a.path}\``;
    case 'process':
      return `\`${a.process}\``;
    case 'github':
      return `\`${a.repo}\` (${(a.reasons ?? []).join(', ')})`;
    case 'mcp':
      return `\`${a.server}\` in \`${a.config}\`${a.url ? ` (url: \`${a.url}\`)` : ''}`;
    default:
      return '`' + JSON.stringify(a) + '`';
  }
}

function groupByFamily(findings) {
  const map = new Map();
  for (const f of findings) {
    const key = f.indicator.attack_family;
    if (!map.has(key)) map.set(key, []);
    map.get(key).push(f);
  }
  return map;
}
