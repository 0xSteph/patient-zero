import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { renderSarif } from '../src/sarif-reporter.js';

const HERE = path.dirname(fileURLToPath(import.meta.url));

async function loadIocs() {
  return JSON.parse(await readFile(path.join(HERE, 'fixtures/iocs-test-extended.json'), 'utf8'));
}

function buildArgs(overrides = {}) {
  return {
    iocs: overrides.iocs,
    findings: overrides.findings ?? [],
    scanned: overrides.scanned ?? {},
    errors: overrides.errors ?? [],
    durationMs: overrides.durationMs ?? 100,
    iocSource: overrides.iocSource ?? 'bundled',
  };
}

test('renderSarif: produces a valid SARIF v2.1.0 envelope with empty findings', async () => {
  const iocs = await loadIocs();
  const sarif = renderSarif(buildArgs({ iocs }));

  assert.equal(sarif.version, '2.1.0');
  assert.ok(sarif.$schema?.includes('sarif-schema-2.1.0'));
  assert.equal(sarif.runs.length, 1);
  assert.equal(sarif.runs[0].tool.driver.name, 'patient-zero');
  assert.deepEqual(sarif.runs[0].results, []);
  assert.deepEqual(sarif.runs[0].tool.driver.rules, []);
  assert.equal(sarif.runs[0].invocations[0].executionSuccessful, true);
});

test('renderSarif: every finding produces a result + a rule (deduped by rule id)', async () => {
  const iocs = await loadIocs();
  const findings = [
    {
      indicator: iocs.indicators.file[0],
      artifact: { path: '/Users/me/Library/LaunchAgents/com.gh-token-monitor.thing.plist' },
    },
    {
      indicator: iocs.indicators.process[0],
      artifact: { process: 'gh-token-monitor' },
    },
    // duplicate rule id — should not produce a second rule entry
    {
      indicator: iocs.indicators.file[0],
      artifact: { path: '/Users/me/Library/LaunchAgents/com.gh-token-monitor.other.plist' },
    },
  ];
  const sarif = renderSarif(buildArgs({ iocs, findings }));

  assert.equal(sarif.runs[0].results.length, 3, '3 findings = 3 results');
  assert.equal(sarif.runs[0].tool.driver.rules.length, 2, '3 findings spanning 2 rule ids = 2 rules');

  // First two results map to different rule indexes; third one shares first
  assert.equal(sarif.runs[0].results[0].ruleIndex, 0);
  assert.equal(sarif.runs[0].results[1].ruleIndex, 1);
  assert.equal(sarif.runs[0].results[2].ruleIndex, 0);
});

test('renderSarif: critical severity maps to level=error + security-severity ≥ 7', async () => {
  const iocs = await loadIocs();
  const findings = [
    { indicator: iocs.indicators.file[0], artifact: { path: '/foo.plist' } },
  ];
  const sarif = renderSarif(buildArgs({ iocs, findings }));
  assert.equal(sarif.runs[0].results[0].level, 'error');
  const sev = sarif.runs[0].tool.driver.rules[0].properties['security-severity'];
  assert.ok(parseFloat(sev) >= 7.0, `expected ≥7.0, got ${sev}`);
});

test('renderSarif: destructive_failsafe surfaced in result properties + message', async () => {
  const iocs = await loadIocs();
  const findings = [
    { indicator: iocs.indicators.file[0], artifact: { path: '/foo.plist' } },
  ];
  const sarif = renderSarif(buildArgs({ iocs, findings }));
  const result = sarif.runs[0].results[0];
  assert.equal(result.properties.destructive_failsafe, true);
  assert.match(result.message.text, /destructive failsafe/i);
});

test('renderSarif: package finding includes lockfile as artifactLocation.uri', async () => {
  const iocs = await loadIocs();
  iocs.indicators.package = [
    {
      id: 'TEST-pkg-1',
      type: 'package',
      attack_family: 'test-attack',
      severity: 'critical',
      first_seen: '2026-01-01',
      last_updated: '2026-01-01',
      source: 'manual',
      description: 'test',
      ecosystem: 'npm',
      name: 'bad',
      versions: '1.0.0',
      version_range: 'exact',
      remediation: { what_to_do: ['x'], commands: [] },
    },
  ];
  const findings = [
    {
      indicator: iocs.indicators.package[0],
      artifact: { lockfile: 'app/package-lock.json', name: 'bad', version: '1.0.0' },
    },
  ];
  const sarif = renderSarif(buildArgs({ iocs, findings }));
  const loc = sarif.runs[0].results[0].locations[0];
  assert.equal(loc.physicalLocation.artifactLocation.uri, 'app/package-lock.json');
});

test('renderSarif: tool driver properties capture IoC database metadata', async () => {
  const iocs = await loadIocs();
  const sarif = renderSarif(buildArgs({ iocs, iocSource: 'fetched' }));
  const props = sarif.runs[0].tool.driver.properties;
  assert.equal(props.ioc_source, 'fetched');
  assert.equal(props.attack_family_count, iocs.attack_family_count);
  assert.deepEqual(props.coverage_window, iocs.coverage_window);
});
