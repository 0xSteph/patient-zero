import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { platform } from 'node:os';

const execFileAsync = promisify(execFile);

/**
 * Process scanner — list running processes and match names against IoC process_names.
 *
 * @param {Object} iocs
 * @param {{ processList?: () => Promise<string[]>, platform?: string }} [options]
 * @returns {Promise<{ findings: Array, scanned: { processes_checked: number }, errors: string[] }>}
 */
export async function scan(iocs, options = {}) {
  const plat = options.platform ?? platform();
  const platformKey = plat === 'darwin' ? 'darwin' : plat === 'win32' ? 'win32' : 'linux';
  const processIndicators = iocs?.indicators?.process ?? [];
  const findings = [];
  const errors = [];

  let processNames;
  try {
    processNames = options.processList ? await options.processList() : await listProcesses(plat);
  } catch (err) {
    errors.push(`failed to list processes: ${err.message}`);
    return { findings, scanned: { processes_checked: 0 }, errors };
  }

  for (const indicator of processIndicators) {
    const platforms = indicator.platforms ?? ['all'];
    if (!platforms.includes('all') && !platforms.includes(platformKey)) continue;

    const targetNames = new Set((indicator.process_names ?? []).map((s) => s.toLowerCase()));
    if (targetNames.size === 0) continue;

    for (const procName of processNames) {
      if (targetNames.has(procName.toLowerCase())) {
        findings.push({ indicator, artifact: { process: procName } });
      }
    }
  }

  return {
    findings,
    scanned: { processes_checked: processNames.length },
    errors,
  };
}

async function listProcesses(plat) {
  if (plat === 'win32') {
    const { stdout } = await execFileAsync('tasklist', ['/FO', 'CSV', '/NH']);
    return stdout
      .split('\n')
      .map((l) => l.split(',')[0]?.replace(/^"|"$/g, '').trim())
      .filter(Boolean);
  }
  // darwin + linux + others: ps
  const { stdout } = await execFileAsync('ps', ['-A', '-o', 'comm=']);
  return stdout
    .split('\n')
    .map((l) => {
      const trimmed = l.trim();
      if (!trimmed) return null;
      // `comm` is the basename; defend against full-path values just in case
      return trimmed.split('/').pop();
    })
    .filter(Boolean);
}
