#!/usr/bin/env node
/**
 * Aggregator entry point. Fetches IoCs from all configured sources, merges, validates,
 * writes data/iocs.json and regenerates docs/ATTACKS.md.
 *
 * Usage:
 *   node aggregator/build.js                  (all sources)
 *   node aggregator/build.js --manual-only    (skip OSV + GHSA — useful for offline test)
 *   node aggregator/build.js --no-write       (compute but don't write files)
 */

import { writeFile } from 'node:fs/promises';
import path from 'node:path';
import { fetchManual } from './sources/manual.js';
import { fetchOsv } from './sources/osv.js';
import { fetchGithubAdvisories } from './sources/github-advisories.js';
import { merge } from './normalize.js';
import { validate } from './validate.js';
import { renderAttacks } from './render-attacks.js';

const SCHEMA_VERSION = '1.0';
const GENERATOR_VERSION = '0.1.0';
const OUTPUT_IOCS = path.resolve(process.cwd(), 'data/iocs.json');
const OUTPUT_ATTACKS = path.resolve(process.cwd(), 'docs/ATTACKS.md');

async function main() {
  const argv = new Set(process.argv.slice(2));
  const manualOnly = argv.has('--manual-only');
  const noWrite = argv.has('--no-write');

  const tasks = [fetchManual()];
  if (!manualOnly) {
    tasks.push(fetchOsv(), fetchGithubAdvisories());
  }

  const sources = await Promise.all(tasks);
  const merged = merge(sources);

  const doc = {
    schema_version: SCHEMA_VERSION,
    generated_at: new Date().toISOString(),
    coverage_window: merged.coverage_window,
    attack_family_count: merged.attack_family_count,
    indicator_count: merged.indicator_count,
    generator: {
      name: 'patient-zero-aggregator',
      version: GENERATOR_VERSION,
      run_id: process.env.GITHUB_RUN_ID ?? 'local',
    },
    sources: merged.sources,
    attack_families: merged.attack_families,
    indicators: merged.indicators,
    indexes: merged.indexes,
  };

  const validation = validate(doc);
  if (!validation.ok) {
    console.error('Validation failed:');
    for (const err of validation.errors) console.error(`  - ${err}`);
    process.exit(2);
  }

  const attacksMarkdown = renderAttacks(doc);

  if (!noWrite) {
    await writeFile(OUTPUT_IOCS, JSON.stringify(doc, null, 2) + '\n', 'utf8');
    await writeFile(OUTPUT_ATTACKS, attacksMarkdown, 'utf8');
  }

  reportSummary(doc, noWrite);
}

function reportSummary(doc, noWrite) {
  const okSources = doc.sources.filter((s) => s.status === 'ok').length;
  const naSources = doc.sources.filter((s) => s.status === 'not_implemented').length;
  const errSources = doc.sources.filter((s) => s.status === 'error').length;

  console.log(`patient-zero aggregator complete${noWrite ? ' (dry run)' : ''}`);
  console.log(`  schema_version:  ${doc.schema_version}`);
  console.log(`  attack_families: ${doc.attack_family_count}`);
  console.log(`  indicators:      ${doc.indicator_count}`);
  console.log(`  coverage:        ${doc.coverage_window.start} → ${doc.coverage_window.end}`);
  console.log(`  sources:         ${okSources} ok / ${naSources} not-implemented / ${errSources} error`);
  for (const s of doc.sources) {
    const tag = s.status === 'ok' ? '✓' : s.status === 'not_implemented' ? '·' : '✗';
    console.log(`    ${tag} ${s.name} (${s.status})${s.error ? ': ' + s.error : ''}`);
  }
  if (!noWrite) {
    console.log(`  wrote:           ${path.relative(process.cwd(), OUTPUT_IOCS)}`);
    console.log(`  wrote:           ${path.relative(process.cwd(), OUTPUT_ATTACKS)}`);
  }
}

main().catch((err) => {
  console.error('aggregator failed:', err);
  process.exit(2);
});
