/**
 * Render scan results as SARIF v2.1.0 (Static Analysis Results Interchange Format).
 *
 * SARIF is the lingua franca for code-scanning results across security tools.
 * GitHub's Security tab natively understands SARIF — uploading via
 * `github/codeql-action/upload-sarif` populates per-file inline annotations
 * AND the Security tab summary view.
 *
 * Spec: https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html
 */

const SARIF_VERSION = '2.1.0';
const TOOL_NAME = 'patient-zero';
const TOOL_INFO_URI = 'https://github.com/0xSteph/patient-zero';

const SEVERITY_TO_SARIF = {
  critical: { level: 'error', securitySeverity: '9.5' },
  high: { level: 'error', securitySeverity: '7.5' },
  medium: { level: 'warning', securitySeverity: '5.0' },
  low: { level: 'warning', securitySeverity: '3.0' },
  info: { level: 'note', securitySeverity: '1.0' },
};

/**
 * @param {{
 *   iocs: Object,
 *   findings: Array,
 *   scanned: Object,
 *   errors: string[],
 *   durationMs: number,
 *   iocSource: string,
 * }} args
 * @returns {Object} SARIF v2.1.0 document
 */
export function renderSarif(args) {
  const { iocs, findings } = args;

  // SARIF rules are the catalog of *possible* findings. We build one rule per
  // distinct IoC ID surfaced in this scan, plus the IoC's metadata.
  const rules = [];
  const ruleIndex = new Map();
  for (const f of findings) {
    const id = f.indicator.id;
    if (ruleIndex.has(id)) continue;
    ruleIndex.set(id, rules.length);
    const fam = iocs.attack_families?.[f.indicator.attack_family];
    rules.push({
      id,
      name: `${f.indicator.attack_family}/${f.indicator.type}`,
      shortDescription: { text: clamp(f.indicator.description, 120) },
      fullDescription: { text: f.indicator.description },
      helpUri: fam?.primary_external_source?.url ?? TOOL_INFO_URI,
      properties: {
        'security-severity': SEVERITY_TO_SARIF[f.indicator.severity]?.securitySeverity ?? '5.0',
        tags: ['security', 'supply-chain', f.indicator.attack_family],
      },
    });
  }

  // SARIF results are the actual matches found.
  const results = findings.map((f) => {
    const sev = SEVERITY_TO_SARIF[f.indicator.severity] ?? SEVERITY_TO_SARIF.medium;
    const location = sarifLocation(f);
    const message = renderResultMessage(f, iocs);
    return {
      ruleId: f.indicator.id,
      ruleIndex: ruleIndex.get(f.indicator.id),
      level: sev.level,
      message: { text: message },
      locations: location ? [location] : [],
      properties: {
        attack_family: f.indicator.attack_family,
        attack_family_display: iocs.attack_families?.[f.indicator.attack_family]?.display_name ?? null,
        destructive_failsafe: iocs.attack_families?.[f.indicator.attack_family]?.destructive_failsafe ?? false,
      },
    };
  });

  return {
    version: SARIF_VERSION,
    $schema: 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json',
    runs: [
      {
        tool: {
          driver: {
            name: TOOL_NAME,
            informationUri: TOOL_INFO_URI,
            version: process.env.PATIENT_ZERO_VERSION ?? '0.2.0-pre.1',
            rules,
            properties: {
              ioc_source: args.iocSource,
              coverage_window: iocs.coverage_window,
              attack_family_count: iocs.attack_family_count,
              indicator_count: iocs.indicator_count,
            },
          },
        },
        invocations: [
          {
            executionSuccessful: args.errors.length === 0 || findings.length > 0,
            startTimeUtc: new Date(Date.now() - args.durationMs).toISOString(),
            endTimeUtc: new Date().toISOString(),
            toolExecutionNotifications: args.errors.map((e) => ({
              level: 'warning',
              message: { text: e },
            })),
          },
        ],
        results,
      },
    ],
  };
}

function sarifLocation(finding) {
  switch (finding.indicator.type) {
    case 'package': {
      // GitHub's Security tab links to a file. Lockfile is the right anchor.
      const lockfile = finding.artifact.lockfile;
      if (!lockfile) return null;
      return {
        physicalLocation: {
          artifactLocation: { uri: lockfile },
        },
        logicalLocations: [
          {
            name: `${finding.artifact.name}@${finding.artifact.version}`,
            kind: 'package',
          },
        ],
      };
    }
    case 'file':
      return finding.artifact.path
        ? { physicalLocation: { artifactLocation: { uri: finding.artifact.path } } }
        : null;
    case 'mcp':
      return finding.artifact.config
        ? { physicalLocation: { artifactLocation: { uri: finding.artifact.config } } }
        : null;
    case 'process':
      // No file location for processes; encode in logicalLocations
      return {
        logicalLocations: [{ name: finding.artifact.process, kind: 'process' }],
      };
    case 'github':
      return {
        logicalLocations: [{ name: finding.artifact.repo, kind: 'repository' }],
      };
    default:
      return null;
  }
}

function renderResultMessage(finding, iocs) {
  const fam = iocs.attack_families?.[finding.indicator.attack_family];
  const famName = fam?.display_name ?? finding.indicator.attack_family;
  let msg = `${famName}: ${finding.indicator.description}`;
  if (fam?.destructive_failsafe) {
    msg += ' This attack family has a destructive failsafe — do NOT revoke tokens until the host is isolated.';
  }
  const rem = finding.indicator.remediation?.what_to_do;
  if (rem?.length) msg += ` Next steps: ${rem.slice(0, 2).join('; ')}`;
  return clamp(msg, 1000);
}

function clamp(s, n) {
  if (!s) return '';
  return s.length <= n ? s : s.slice(0, n - 1) + '…';
}
