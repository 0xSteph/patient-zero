#!/usr/bin/env node
import { writeFile } from 'node:fs/promises';
import { Command } from 'commander';
import ora from 'ora';
import pc from 'picocolors';

import { loadIocs } from '../src/ioc-loader.js';
import { renderTerminal, renderJson } from '../src/reporter.js';
import { renderMarkdown } from '../src/markdown-reporter.js';
import { renderSarif } from '../src/sarif-reporter.js';
import { scan as scanLockfiles } from '../src/scanners/lockfiles.js';
import { scan as scanMcp } from '../src/scanners/mcp.js';
import { scan as scanLocalFiles } from '../src/scanners/local-files.js';
import { scan as scanProcesses } from '../src/scanners/processes.js';
import { scan as scanGithub } from '../src/scanners/github.js';
import { runInterceptor } from '../src/install-interceptor.js';
import { installHook, removeHook, detectHookSystem } from '../src/hook-installer.js';

const VERSION = '0.2.0-pre.1';

// Exit code contract — see README. Do not change without bumping major.
const EXIT_CLEAN = 0;
const EXIT_FINDING = 1;
const EXIT_ERROR = 2;

const program = new Command();
program
  .name('patient-zero')
  .description('Scans Node, Python, and AI-agent configs for supply-chain attack IoCs.')
  .version(VERSION, '-v, --version');

// Default "scan" command — invoked when no subcommand specified.
program
  .command('scan', { isDefault: true })
  .description('Scan the current machine for known IoCs')
  .option('--dir <path>', 'directory to scan (default: cwd)', process.cwd())
  .option('--depth <n>', 'max directory depth for lockfile search', '5')
  .option('--ecosystem <name>', 'restrict to one ecosystem: npm|pypi')
  .option('--no-github', 'skip GitHub account scan (default off if non-TTY)')
  .option('--github', 'force-enable GitHub account scan')
  .option('--offline', 'use bundled IoC snapshot; never reach the network')
  .option('--json', 'emit JSON output instead of pretty terminal')
  .option('--report <file>', 'also write a markdown report to <file>')
  .option('--sarif <file>', 'also write a SARIF v2.1.0 file (for GitHub Security tab)')
  .option('--debug', 'verbose error output')
  .action(runScan);

// New v0.2 subcommand: install interceptor.
program
  .command('install <pkg...>')
  .description('Resolve a proposed install, scan it against IoCs, block on hit')
  .option('--pm <name>', 'force package manager: npm|pnpm|yarn (default: detect from lockfile)')
  .option('--offline', 'use bundled IoC snapshot; never reach the network')
  .option('--json', 'emit JSON output')
  .option('--debug', 'verbose error output')
  .action(runInstall);

// install-hook subcommand: wire patient-zero into the project's pre-commit pipeline.
program
  .command('install-hook')
  .description('Install patient-zero as a pre-commit hook (husky / lefthook / pre-commit / native)')
  .option('--system <name>', 'force a specific system: husky|lefthook|pre-commit|native')
  .option('--remove', 'remove the patient-zero hook instead of installing it')
  .option('--json', 'emit JSON output')
  .action(runInstallHook);

program.parseAsync(process.argv).catch((err) => {
  process.stderr.write(pc.red(`patient-zero: fatal: ${err.message}\n`));
  process.exit(EXIT_ERROR);
});

// ---------- scan (default) ----------

async function runScan(opts) {
  try {
    await runScanImpl(opts);
  } catch (err) {
    process.stderr.write(pc.red(`patient-zero: fatal: ${err.message}\n`));
    if (opts.debug) process.stderr.write(err.stack + '\n');
    process.exit(EXIT_ERROR);
  }
}

async function runScanImpl(opts) {
  const start = process.hrtime.bigint();
  const useSpinners = !opts.json && process.stdout.isTTY;
  const spinner = useSpinners ? ora({ text: 'Loading IoC database…', color: 'cyan' }).start() : null;

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

  // Decide whether to run the GitHub scanner
  const githubExplicit = process.argv.includes('--github');
  const githubExplicitOff = process.argv.includes('--no-github');
  let runGithub;
  if (githubExplicit) runGithub = true;
  else if (githubExplicitOff) runGithub = false;
  else runGithub = false; // default off

  const scanSpinner = useSpinners ? ora({ text: 'Scanning…', color: 'cyan' }).start() : null;
  const [rLockfiles, rMcp, rLocalFiles, rProcesses, rGithub] = await Promise.all([
    scanLockfiles(iocs, { root: opts.dir, depth: parseInt(opts.depth, 10), ecosystem: opts.ecosystem }),
    scanMcp(iocs),
    scanLocalFiles(iocs),
    scanProcesses(iocs),
    scanGithub(iocs, { enabled: runGithub }),
  ]);
  scanSpinner?.succeed('Scan complete');

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
  const reportArgs = { iocs, findings: allFindings, scanned, errors: allErrors, skipped, durationMs, iocSource, iocAgeMs };

  if (opts.json) process.stdout.write(renderJson(reportArgs) + '\n');
  else process.stdout.write(renderTerminal(reportArgs));

  if (opts.report) {
    try {
      await writeFile(opts.report, renderMarkdown(reportArgs), 'utf8');
      if (!opts.json) process.stdout.write(pc.dim(`Markdown report written: ${opts.report}\n\n`));
    } catch (err) {
      process.stderr.write(pc.red(`patient-zero: failed to write report: ${err.message}\n`));
    }
  }

  if (opts.sarif) {
    try {
      await writeFile(opts.sarif, JSON.stringify(renderSarif(reportArgs), null, 2) + '\n', 'utf8');
      if (!opts.json) process.stdout.write(pc.dim(`SARIF report written: ${opts.sarif}\n\n`));
    } catch (err) {
      process.stderr.write(pc.red(`patient-zero: failed to write SARIF: ${err.message}\n`));
    }
  }

  if (allErrors.length > 0 && allFindings.length === 0) process.exit(EXIT_ERROR);
  if (allFindings.some((f) => severityRank(f.indicator.severity) <= severityRank('medium'))) process.exit(EXIT_FINDING);
  process.exit(EXIT_CLEAN);
}

// ---------- install (new v0.2) ----------

async function runInstall(pkgs, opts) {
  try {
    await runInstallImpl(pkgs, opts);
  } catch (err) {
    process.stderr.write(pc.red(`patient-zero install: fatal: ${err.message}\n`));
    if (opts.debug) process.stderr.write(err.stack + '\n');
    process.exit(EXIT_ERROR);
  }
}

async function runInstallImpl(pkgs, opts) {
  const useSpinners = !opts.json && process.stdout.isTTY;
  const spinner = useSpinners ? ora({ text: 'Loading IoC database…', color: 'cyan' }).start() : null;

  const { iocs, source: iocSource } = await loadIocs({ offline: Boolean(opts.offline) });
  spinner?.succeed(`IoC database loaded (${iocSource}, ${iocs.attack_family_count} families · ${iocs.indicator_count} indicators)`);

  const resolveSpinner = useSpinners ? ora({ text: `Resolving install tree for ${pkgs.join(', ')}…`, color: 'cyan' }).start() : null;

  const result = await runInterceptor({
    pkgs,
    iocs,
    pm: opts.pm,
    onProgress: (event, data) => {
      if (event === 'detect') resolveSpinner && (resolveSpinner.text = `Resolving install (${data.pm})…`);
      if (event === 'resolved') resolveSpinner?.succeed(`Resolved ${data.count} packages`);
      if (event === 'scanned' && data.findings === 0) {
        if (useSpinners) process.stdout.write(pc.green(`✅  No known IoCs in proposed install. Passing through.\n\n`));
      }
    },
  });

  if (result.error) {
    resolveSpinner?.fail(result.error);
    process.stderr.write(pc.red(`patient-zero install: ${result.error}\n`));
    if (opts.debug) process.stderr.write(`hint: try running the dry-run manually:\n  npm install --package-lock-only --dry-run --json ${pkgs.join(' ')}\n`);
    process.exit(EXIT_ERROR);
  }

  if (opts.json) {
    process.stdout.write(JSON.stringify({
      mode: 'install-interceptor',
      pm: result.pm,
      resolvedCount: result.resolvedCount,
      findings: result.findings.map((f) => ({
        id: f.indicator.id,
        severity: f.indicator.severity,
        attack_family: f.indicator.attack_family,
        name: f.artifact.name,
        version: f.artifact.version,
        description: f.indicator.description,
        remediation: f.indicator.remediation,
      })),
      passedThrough: result.passedThrough,
      exitCode: result.exitCode,
    }, null, 2) + '\n');
  } else if (result.findings.length > 0) {
    process.stdout.write('\n');
    process.stdout.write(pc.bgRed(pc.white(pc.bold(`  ❌  patient-zero blocked the install  `))) + '\n\n');
    process.stdout.write(pc.red(`Found ${result.findings.length} indicator${result.findings.length === 1 ? '' : 's'} of compromise in the proposed install tree.\n`));
    process.stdout.write(pc.red(`Postinstall scripts have NOT run.\n\n`));
    for (const f of result.findings) {
      process.stdout.write(`  ${pc.bold(f.indicator.severity.toUpperCase())} · ${f.indicator.id}\n`);
      process.stdout.write(`     ${f.artifact.name}@${f.artifact.version}\n`);
      process.stdout.write(`     ${pc.dim(f.indicator.description)}\n`);
      if (f.indicator.remediation?.what_to_do?.length) {
        process.stdout.write(`     ${pc.bold('What to do:')}\n`);
        for (const step of f.indicator.remediation.what_to_do) process.stdout.write(`       • ${step}\n`);
      }
      process.stdout.write('\n');
    }
    process.stdout.write(pc.dim(`To force install anyway (NOT recommended): use the underlying package manager directly.\n\n`));
  }

  process.exit(result.exitCode);
}

function severityRank(s) {
  return { critical: 0, high: 1, medium: 2, low: 3, info: 4 }[s] ?? 99;
}

// ---------- install-hook (new v0.2) ----------

async function runInstallHook(opts) {
  try {
    if (opts.remove) {
      const result = await removeHook({});
      if (opts.json) {
        process.stdout.write(JSON.stringify({ mode: 'install-hook', action: 'remove', ...result }, null, 2) + '\n');
      } else if (result.removed.length === 0) {
        process.stdout.write(pc.dim('No patient-zero hook found to remove.\n'));
      } else {
        process.stdout.write(pc.green('✅  Removed patient-zero hook:\n'));
        for (const p of result.removed) process.stdout.write(`     ${p}\n`);
      }
      process.exit(EXIT_CLEAN);
    }

    const result = await installHook({ system: opts.system });
    if (opts.json) {
      process.stdout.write(JSON.stringify({ mode: 'install-hook', action: 'install', ...result }, null, 2) + '\n');
    } else {
      process.stdout.write(pc.green(`✅  Hook ${result.action}: ${result.path} (${result.system})\n`));
      process.stdout.write(pc.dim(`     The hook runs ${pc.bold('npx patient-zero scan')} before every commit.\n`));
      process.stdout.write(pc.dim(`     To remove: ${pc.bold('npx patient-zero install-hook --remove')}\n`));
    }
    process.exit(EXIT_CLEAN);
  } catch (err) {
    process.stderr.write(pc.red(`patient-zero install-hook: ${err.message}\n`));
    process.exit(EXIT_ERROR);
  }
}
