import pc from 'picocolors';

const SEVERITY_ORDER = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
const SEVERITY_STYLES = {
  critical: { glyph: '❌', color: pc.red, label: 'CRITICAL' },
  high: { glyph: '❌', color: pc.red, label: 'HIGH' },
  medium: { glyph: '⚠️ ', color: pc.yellow, label: 'MEDIUM' },
  low: { glyph: '⚠️ ', color: pc.yellow, label: 'LOW' },
  info: { glyph: 'ℹ️ ', color: pc.dim, label: 'INFO' },
};

/**
 * Render scan results to the terminal.
 *
 * @param {{
 *   iocs: Object,
 *   findings: Array<{indicator: Object, artifact: Object, scannerName: string}>,
 *   scanned: Object,
 *   errors: string[],
 *   skipped: string[],
 *   durationMs: number,
 *   iocSource: string,
 *   iocAgeMs: number,
 * }} args
 * @returns {string} the rendered text (write to stdout via the caller)
 */
export function renderTerminal(args) {
  const { iocs, findings, scanned, errors, skipped, durationMs, iocSource, iocAgeMs } = args;
  const lines = [];
  const header = pc.bold(`patient-zero v${packageVersion()}`);
  lines.push('');
  lines.push(header);
  lines.push('');

  // 1. Destructive-failsafe banner FIRST if any finding is in a destructive-failsafe family.
  const failsafeFindings = findings.filter((f) => {
    const fam = iocs.attack_families?.[f.indicator.attack_family];
    return fam?.destructive_failsafe === true;
  });
  if (failsafeFindings.length > 0) {
    const families = new Set(failsafeFindings.map((f) => iocs.attack_families[f.indicator.attack_family].display_name));
    lines.push(pc.bgRed(pc.white(pc.bold('  ❌  DESTRUCTIVE FAILSAFE DETECTED  '))));
    lines.push('');
    lines.push(pc.red(`  ${[...families].join(', ')} has a known destructive failsafe.`));
    lines.push(pc.red(`  Do NOT revoke npm or GitHub tokens until the host is isolated.`));
    lines.push(pc.red(`  Read: ${pc.bold('docs/SHAI-HULUD-FAILSAFE.md')} before any defensive action.`));
    lines.push('');
  }

  if (findings.length === 0) {
    lines.push(`${pc.green('✅')}  No known IoCs matched.`);
    lines.push('');
  } else {
    lines.push(pc.bold('Findings'));
    lines.push(pc.dim('────────'));
    lines.push('');

    const byFamily = groupByFamily(findings);
    for (const [familyKey, group] of byFamily) {
      const fam = iocs.attack_families?.[familyKey];
      const famName = fam?.display_name ?? familyKey;
      lines.push(pc.bold(famName));
      group.sort((a, b) => (SEVERITY_ORDER[a.indicator.severity] ?? 99) - (SEVERITY_ORDER[b.indicator.severity] ?? 99));
      for (const finding of group) {
        lines.push(...renderFinding(finding));
      }
      lines.push('');
    }
  }

  // Summary line
  lines.push(pc.dim(renderScanLine(scanned, skipped)));
  lines.push(pc.dim(renderMetaLine(iocs, durationMs, iocSource, iocAgeMs)));

  if (errors.length > 0) {
    lines.push('');
    lines.push(pc.yellow(`Scanner errors (${errors.length}):`));
    for (const e of errors) lines.push(pc.yellow(`  - ${e}`));
  }

  lines.push('');
  return lines.join('\n');
}

function renderFinding(finding) {
  const lines = [];
  const ind = finding.indicator;
  const style = SEVERITY_STYLES[ind.severity] ?? SEVERITY_STYLES.info;
  lines.push(`  ${style.glyph} ${style.color(style.label)} · ${pc.dim(ind.id)}`);

  // Artifact line — varies by indicator type
  lines.push(`     ${renderArtifact(finding)}`);

  // Remediation
  const rem = ind.remediation;
  if (rem?.what_to_do?.length) {
    lines.push(`     ${pc.bold('What to do:')}`);
    for (const step of rem.what_to_do) lines.push(`       • ${step}`);
  }
  if (rem?.commands?.length) {
    lines.push(`     ${pc.bold('Commands:')}`);
    for (const cmd of rem.commands) lines.push(`       ${pc.cyan('$')} ${pc.cyan(cmd)}`);
  }

  // Source link
  const src = ind.references?.[0];
  if (src) lines.push(`     ${pc.dim('Source:')} ${pc.dim(src)}`);

  return lines;
}

function renderArtifact(finding) {
  const { indicator: ind, artifact: art } = finding;
  switch (ind.type) {
    case 'package':
      return `${pc.bold('Package:')} ${art.name}@${art.version} in ${art.lockfile}`;
    case 'file':
      return `${pc.bold('File:')} ${art.path}`;
    case 'process':
      return `${pc.bold('Process:')} ${art.process}`;
    case 'github':
      return `${pc.bold('Repo:')} ${art.repo}${art.reasons ? ` (${art.reasons.join(', ')})` : ''}`;
    case 'network':
      return `${pc.bold('Network:')} ${art.value ?? JSON.stringify(art)}`;
    case 'mcp':
      return `${pc.bold('MCP server:')} ${art.server} in ${art.config}${art.url ? ` (url: ${art.url})` : ''}`;
    default:
      return JSON.stringify(art);
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

function renderScanLine(scanned, skipped) {
  const parts = [];
  if (scanned.lockfiles_found != null) parts.push(`${scanned.lockfiles_found} lockfiles`);
  if (scanned.processes_checked != null) parts.push(`${scanned.processes_checked} processes`);
  if (scanned.configs_found != null) parts.push(`${scanned.configs_found} MCP configs`);
  if (scanned.repos_checked != null) parts.push(`${scanned.repos_checked} repos`);
  if (scanned.paths_checked != null) parts.push(`${scanned.paths_checked} paths checked`);
  let line = parts.length > 0 ? `Scanned ${parts.join(' · ')}` : 'Nothing scanned.';
  if (skipped?.length) line += `  (skipped: ${skipped.join(', ')})`;
  return line;
}

function renderMetaLine(iocs, durationMs, iocSource, iocAgeMs) {
  const seconds = (durationMs / 1000).toFixed(2);
  const window = `${iocs.coverage_window?.start ?? '—'} → ${iocs.coverage_window?.end ?? '—'}`;
  const sourceLabels = {
    fetched: 'fresh',
    'cache-fresh': 'cache (fresh)',
    'cache-stale': pc.yellow('cache (stale, network failed)'),
    bundled: pc.yellow('bundled (offline)'),
  };
  const sourceLabel = sourceLabels[iocSource] ?? iocSource;
  const ageNote = iocSource === 'cache-stale' || iocSource === 'bundled' ? '' : ` · ${formatAge(iocAgeMs)}`;
  return `${seconds}s · coverage ${window} · ${iocs.attack_family_count ?? '?'} families · ${iocs.indicator_count ?? '?'} indicators · IoC: ${sourceLabel}${ageNote}`;
}

function formatAge(ms) {
  if (ms < 60_000) return 'just now';
  const min = Math.round(ms / 60_000);
  if (min < 60) return `${min}m ago`;
  const hr = Math.round(ms / 3_600_000);
  return `${hr}h ago`;
}

function packageVersion() {
  return process.env.PATIENT_ZERO_VERSION ?? 'dev';
}

/**
 * Render scan results as JSON for CI consumption.
 */
export function renderJson(args) {
  return JSON.stringify(
    {
      schema_version: '1.0',
      patient_zero_version: packageVersion(),
      scanned_at: new Date().toISOString(),
      duration_ms: args.durationMs,
      ioc: {
        source: args.iocSource,
        age_ms: args.iocAgeMs,
        coverage_window: args.iocs.coverage_window,
        attack_family_count: args.iocs.attack_family_count,
        indicator_count: args.iocs.indicator_count,
      },
      scanned: args.scanned,
      skipped: args.skipped,
      errors: args.errors,
      findings: args.findings.map((f) => ({
        id: f.indicator.id,
        type: f.indicator.type,
        attack_family: f.indicator.attack_family,
        attack_family_display: args.iocs.attack_families?.[f.indicator.attack_family]?.display_name ?? null,
        destructive_failsafe: args.iocs.attack_families?.[f.indicator.attack_family]?.destructive_failsafe ?? false,
        severity: f.indicator.severity,
        description: f.indicator.description,
        artifact: f.artifact,
        remediation: f.indicator.remediation,
        references: f.indicator.references ?? [],
      })),
    },
    null,
    2,
  );
}
