import { execFile } from 'node:child_process';
import { promisify } from 'node:util';

const execFileAsync = promisify(execFile);

/**
 * GitHub account scanner. Lists the authenticated user's repos via `gh` CLI
 * (or via a PAT-based fetch if a token is supplied), then matches repo metadata
 * against IoC github indicators.
 *
 * Scoped to user-repos in v0.1.
 *
 * @param {Object} iocs
 * @param {{ enabled?: boolean, token?: string, repoList?: () => Promise<Array>, ghCommand?: string }} [options]
 * @returns {Promise<{ findings: Array, scanned: { repos_checked: number }, errors: string[], skipped?: string }>}
 */
export async function scan(iocs, options = {}) {
  if (options.enabled === false) {
    return { findings: [], scanned: { repos_checked: 0 }, errors: [], skipped: 'disabled by --no-github' };
  }

  const githubIndicators = iocs?.indicators?.github ?? [];
  const findings = [];
  const errors = [];

  let repos;
  try {
    if (options.repoList) {
      repos = await options.repoList();
    } else if (options.token) {
      repos = await fetchReposViaToken(options.token);
    } else {
      repos = await fetchReposViaGh(options.ghCommand ?? 'gh');
    }
  } catch (err) {
    return {
      findings: [],
      scanned: { repos_checked: 0 },
      errors: [`failed to list GitHub repos: ${err.message}`],
      skipped: 'list-failed',
    };
  }

  for (const indicator of githubIndicators) {
    if (indicator.scope && indicator.scope !== 'user-repos') continue;

    const namePatterns = compileAll(indicator.repo_name_patterns ?? []);
    const descPatterns = compileAll(indicator.repo_description_patterns ?? []);

    for (const repo of repos) {
      const reasons = [];
      for (const re of namePatterns) {
        if (re.test(repo.name ?? '')) reasons.push(`name "${repo.name}" matches /${re.source}/`);
      }
      for (const re of descPatterns) {
        if (re.test(repo.description ?? '')) reasons.push(`description matches /${re.source}/`);
      }
      if (reasons.length > 0) {
        findings.push({ indicator, artifact: { repo: repo.full_name ?? repo.name, reasons } });
      }
    }
  }

  return { findings, scanned: { repos_checked: repos.length }, errors };
}

async function fetchReposViaGh(ghCommand) {
  // Limit to user-owned repos. `gh repo list` defaults to current user; --limit caps results.
  const { stdout } = await execFileAsync(ghCommand, [
    'repo',
    'list',
    '--limit',
    '1000',
    '--json',
    'name,nameWithOwner,description,createdAt',
  ]);
  const arr = JSON.parse(stdout);
  return arr.map((r) => ({
    name: r.name,
    full_name: r.nameWithOwner,
    description: r.description ?? '',
    created_at: r.createdAt,
  }));
}

async function fetchReposViaToken(token) {
  const resp = await fetch('https://api.github.com/user/repos?per_page=100&affiliation=owner', {
    headers: {
      Authorization: `Bearer ${token}`,
      Accept: 'application/vnd.github+json',
      'X-GitHub-Api-Version': '2022-11-28',
    },
  });
  if (!resp.ok) throw new Error(`GitHub API ${resp.status}`);
  const arr = await resp.json();
  return arr.map((r) => ({
    name: r.name,
    full_name: r.full_name,
    description: r.description ?? '',
    created_at: r.created_at,
  }));
}

function compileAll(patterns) {
  const out = [];
  for (const p of patterns) {
    try {
      out.push(new RegExp(p));
    } catch {
      // skip invalid pattern
    }
  }
  return out;
}
