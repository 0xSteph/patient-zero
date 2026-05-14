#!/usr/bin/env node
import { writeFile } from 'node:fs/promises';
import { Command } from 'commander';
import ora from 'ora';
import pc from 'picocolors';

import { loadIocs } from '../src/ioc-loader.js';
import { renderTerminal, renderJson } from '../src/reporter.js';
import { renderMarkdown } from '../src/markdown-reporter.js';
import { scan as scanLockfiles } from '../src/scanners/lockfiles.js';
import { scan as scanMcp } from '../src/scanners/mcp.js';
import { scan as scanLocalFiles } from '../src/scanners/local-files.js';
import { scan as scanProcesses } from '../src/scanners/processes.js';
import { scan as scanGithub } from '../src/scanners/github.js';

const VERSION = '0.1.0-pre.1';

// Exit code contract — see README. Do not change without bumping major.
const EXIT_CLEAN = 0;
const EXIT_FINDING = 1;
const EXIT_ERROR = 2;

const program = new Command();
program
  .name('patient-zero')
  .description('Scans Node, Python, and AI-agent configs for supply-chain attack IoCs.')
  .version(VERSION, '-v, --version')
  .option('--dir <path>', 'directory to scan (default: cwd)', process.cwd())
  .option('--depth <n>', 'max directory depth for lockfile search', '5')
  .option('--ecosystem <name>', 'restrict to one ecosystem: npm|pypi')
  .option('--no-github', 'skip GitHub account scan (default: prompt if TTY, off if non-TTY)')
  .option('--github', 'force-enable GitHub account scan (overrides default-off in non-TTY)')
  .option('--offline', 'use bundled IoC snapshot; never reach the network')
  .option('--json', 'emit JSON output instead of pretty terminal')
  .option('--report <file>', 'also write a markdown report to <file>')
  .option('--debug', 'verbose error output');

program.parse(process.argv);
const opts = program.opts();

main().catch((err) => {
  process.stderr.write(pc.red(`patient-zero: fatal: ${err.message}\n`));
  if (opts.debug) process.stderr.write(err.stack + '\n');
  process.exit(EXIT_ERROR);
});

async function main() {
  const start = process.hrtime.bigint();
  const useSpinners = !opts.json && process.stdout.isTTY;
  const spinner = useSpinners ? ora({ text: 'Loading IoC database…', color: 'cyan' }).start() : null;

  // 1. Load IoCs
  let iocsResult;
  try {
    iocsResult = await loadIocs({ offline: Boolean(opts.offline) });
  } catch (err) {
    spinner?.fail('Failed to load IoC database');
    process.stderr.write(pc.red(`patient-zero: cannot load IoCs: ${err.message}\n`));
    process.exit(EXIT_ERROR);
  }
  const { iocs, source: iocSource, ageMs: iocAgeMs } = iocsResult;
  spinner?.succeed(`IoC database loaded (${iocSource}, ${iocs.attack_family_count} families · ${iocs.indicator_count} indicators)`);

  // 2. Decide whether to run the GitHub scanner
  const githubExplicit = process.argv.includes('--github');
  const githubExplicitOff = process.argv.includes('--no-github');
  let runGithub;
  if (githubExplicit) runGithub = true;
  else if (githubExplicitOff) runGithub = false;
  else runGithub = false; // default off; respects "opt-in" requirement

  // 3. Run scanners in parallel
  const scanSpinner = useSpinners ? ora({ text: 'Scanning…', color: 'cyan' }).start() : null;
  const scannerJobs = [
    scanLockfiles(iocs, { root: opts.dir, depth: parseInt(opts.depth, 10), ecosystem: opts.ecosystem }),
    scanMcp(iocs),
    scanLocalFiles(iocs),
    scanProcesses(iocs),
    scanGithub(iocs, { enabled: runGithub }),
  ];
  const [rLockfiles, rMcp, rLocalFiles, rProcesses, rGithub] = await Promise.all(scannerJobs);
  scanSpinner?.succeed('Scan complete');

  // 4. Aggregate results
  const allFindings = [
    ...rLockfiles.findings,
    ...rMcp.findings,
    ...rLocalFiles.findings,
    ...rProcesses.findings,
    ...rGithub.findings,
  ];
  const allErrors = [
    ...rLockfiles.errors,
    ...rMcp.errors,
    ...rLocalFiles.errors,
    ...rProcesses.errors,
    ...rGithub.errors,
  ];
  const scanned = {
    ...rLockfiles.scanned,
    ...rMcp.scanned,
    ...rLocalFiles.scanned,
    ...rProcesses.scanned,
    ...rGithub.scanned,
  };
  const skipped = [];
  if (rGithub.skipped) skipped.push(`github (${rGithub.skipped})`);

  const durationMs = Number(process.hrtime.bigint() - start) / 1_000_000;

  // 5. Render
  const reportArgs = {
    iocs,
    findings: allFindings,
    scanned,
    errors: allErrors,
    skipped,
    durationMs,
    iocSource,
    iocAgeMs,
  };

  if (opts.json) {
    process.stdout.write(renderJson(reportArgs) + '\n');
  } else {
    process.stdout.write(renderTerminal(reportArgs));
  }

  if (opts.report) {
    try {
      await writeFile(opts.report, renderMarkdown(reportArgs), 'utf8');
      if (!opts.json) process.stdout.write(pc.dim(`Markdown report written: ${opts.report}\n\n`));
    } catch (err) {
      process.stderr.write(pc.red(`patient-zero: failed to write report: ${err.message}\n`));
      // Don't fail the exit code over this — finding semantics still apply
    }
  }

  // 6. Exit per the contract
  if (allErrors.length > 0 && allFindings.length === 0) {
    process.exit(EXIT_ERROR);
  }
  if (allFindings.some((f) => severityRank(f.indicator.severity) <= severityRank('medium'))) {
    process.exit(EXIT_FINDING);
  }
  process.exit(EXIT_CLEAN);
}

function severityRank(s) {
  return { critical: 0, high: 1, medium: 2, low: 3, info: 4 }[s] ?? 99;
}
