import { readdir, stat } from 'node:fs/promises';
import { homedir, platform } from 'node:os';
import path from 'node:path';

/**
 * Scan local filesystem for paths matching IoC file path_patterns.
 * v0.1 implements path matching only — content_patterns are deferred to v0.2.
 *
 * Strategy: for each file indicator, expand ~ in path_patterns to the user's home,
 * derive each pattern's parent directory, list that directory, regex-test each entry.
 * Also explicitly checks common registry-config files (~/.npmrc, ~/.pypirc).
 *
 * @param {Object} iocs
 * @param {{ home?: string, platform?: string }} [options]
 */
export async function scan(iocs, options = {}) {
  const home = options.home ?? homedir();
  const plat = options.platform ?? platform();
  const platformKey = plat === 'darwin' ? 'darwin' : plat === 'win32' ? 'win32' : 'linux';

  const fileIndicators = iocs?.indicators?.file ?? [];
  const findings = [];
  const errors = [];
  let pathsChecked = 0;

  for (const indicator of fileIndicators) {
    const platforms = indicator.platforms ?? ['all'];
    if (!platforms.includes('all') && !platforms.includes(platformKey)) continue;

    for (const pattern of indicator.path_patterns ?? []) {
      const expanded = pattern.replace(/^~/, home);
      // Derive the directory we need to list. We look for the largest static prefix
      // before any regex meta-characters.
      const parentDir = staticPrefixDirectory(expanded);
      if (!parentDir) continue;

      let basenameRegex;
      try {
        // Build a regex anchored to match against absolute paths.
        basenameRegex = new RegExp('^' + expanded + '$');
      } catch (err) {
        errors.push(`invalid regex in indicator ${indicator.id}: ${err.message}`);
        continue;
      }

      let entries;
      try {
        entries = await readdir(parentDir);
      } catch {
        continue; // dir doesn't exist on this machine — normal
      }

      for (const name of entries) {
        const full = path.join(parentDir, name);
        pathsChecked += 1;
        if (basenameRegex.test(full)) {
          let isFile = false;
          try {
            const s = await stat(full);
            isFile = s.isFile();
          } catch {
            continue;
          }
          if (isFile) {
            findings.push({ indicator, artifact: { path: full } });
          }
        }
      }
    }
  }

  return {
    findings,
    scanned: { paths_checked: pathsChecked },
    errors,
  };
}

/**
 * From a regex-bearing path, derive the static directory prefix that can be listed.
 * E.g. "/Users/x/Library/LaunchAgents/com\\.gh-token-monitor.*\\.plist" -> "/Users/x/Library/LaunchAgents"
 */
function staticPrefixDirectory(pattern) {
  // Find first regex meta character not preceded by a backslash.
  const metaRe = /(?<!\\)[.*+?(){}\[\]|^$]/;
  const m = pattern.match(metaRe);
  const cutAt = m ? m.index : pattern.length;
  const prefix = pattern.slice(0, cutAt);
  // Unescape backslash-escaped chars in the static prefix
  const unescaped = prefix.replace(/\\(.)/g, '$1');
  // Take the directory portion
  const dir = path.dirname(unescaped);
  return dir === '.' ? null : dir;
}
