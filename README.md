# patient-zero

Scans Node, Python, and AI-agent configs for indicators of compromise from npm and PyPI supply-chain attacks (Sept 2025 – present). Triage in 30 seconds, block malicious installs before postinstall runs, or wire it into your CI — same IoC database, three modes, one command.

[![npm](https://img.shields.io/npm/v/patient-zero?style=flat-square)](https://www.npmjs.com/package/patient-zero)
[![downloads](https://img.shields.io/npm/dw/patient-zero?style=flat-square)](https://www.npmjs.com/package/patient-zero)
[![ci](https://img.shields.io/github/actions/workflow/status/0xSteph/patient-zero/ci.yml?branch=main&style=flat-square&label=ci)](https://github.com/0xSteph/patient-zero/actions)
[![license](https://img.shields.io/badge/license-MIT-blue?style=flat-square)](LICENSE)
[![node](https://img.shields.io/node/v/patient-zero?style=flat-square)](package.json)
[![telemetry](https://img.shields.io/badge/telemetry-none-2ea44f?style=flat-square)](#how-it-works)
[![signup](https://img.shields.io/badge/signup-none-2ea44f?style=flat-square)](#how-it-works)
[![runs](https://img.shields.io/badge/runs-offline_capable-2ea44f?style=flat-square)](#how-it-works)

```
$ npx patient-zero

Findings
────────

chalk maintainer phish (Sept 2025)
  ❌ CRITICAL · GHSA-demo-chalk
     Package: chalk@4.0.0 in package-lock.json
     What to do:
       • Run `npm ls chalk` to find which workspace pulls this version
       • Pin to a clean version (chalk@5.0.0+) in package.json and re-install
       • Rotate any tokens that were in env during the install window
     Commands:
       $ npm ls chalk
       $ npm install chalk@5.0.0
     Source: https://security.snyk.io/

Scanned 1 lockfiles · 234 processes · 2 MCP configs · 0 repos · 0 paths checked
0.02s · coverage 2025-09-01 → present · 6 families · 47 indicators · IoC: fresh
```

<details><summary>Or watch the 12-second animated demo</summary>

![demo](docs/assets/demo.gif)

</details>

## Three ways to use it

### 1. On-demand triage — when the news breaks

```sh
npx patient-zero@latest
```

No global install, no signup, no config. Runs against the current directory. Use this when chalk / axios / the latest Shai-Hulud variant hits Hacker News and you need a fast yes/no on whether your machine is affected.

### 2. Install-time blocking — catch malware *before* it runs

```sh
npx patient-zero@latest install <package>
```

Resolves the proposed install tree in a sandboxed temp directory, cross-references every transitive dependency against the IoC database, and refuses to proceed if any indicator matches. **Postinstall scripts never execute.** This is the most valuable single feature for the agent era — your AI agent installs things on your behalf; you don't see every install; this catches it.

### 3. Continuous CI — every commit, every PR

```yaml
- uses: 0xSteph/patient-zero@v0.2
  with:
    fail-on: medium
```

Drops into any GitHub Actions workflow. Produces SARIF that populates GitHub's Security tab automatically. No tokens, no Snyk-style signup, no per-seat pricing.

Or as a pre-commit hook:

```sh
npx patient-zero install-hook
```

Auto-detects husky / lefthook / pre-commit / native git hooks and wires patient-zero into the right place. Idempotent and removable.

## What it scans

- **AI-agent MCP configs** — Claude Desktop, Claude Code, Cursor, Cline. Known-malicious servers, typosquats of `@modelcontextprotocol/*`, non-HTTPS URLs, sensitive credentials in env blocks. [Nobody else covers this lane.](docs/MCP-IOC-GUIDE.md)
- **Running processes** — matches known malicious daemons (e.g. Shai-Hulud's `gh-token-monitor`).
- **Local persistence** — `~/Library/LaunchAgents/` (macOS), `~/.config/systemd/user/` (Linux), `~/.npmrc`, `~/.pypirc`.
- **npm + Python lockfiles** — `package-lock.json`, `pnpm-lock.yaml`, `yarn.lock`, `requirements.txt`, `poetry.lock`. Semver-aware version matching.
- **Your GitHub account** (opt-in) — uses `gh` CLI or a PAT you provide. Looks for repos created by stolen credentials matching known attack patterns.

[See the full IoC list →](data/iocs.json) · [Schema →](docs/IOC-SCHEMA.md) · [MCP IoC guide →](docs/MCP-IOC-GUIDE.md)

## What this is NOT

- Not an EDR or runtime sandbox.
- Not a replacement for continuous monitoring tools like Snyk or Socket — works alongside them.
- Not a vulnerability scanner (we scan for known-malicious indicators, not CVEs).

The opinionated bet: most of the value is in *not-on-GitHub* coverage (MCP configs, processes, local persistence) plus install-time blocking. GitHub's Dependabot now covers part of the lockfile-malware lane natively as of March 2026; we focus on the parts it doesn't.

## Covered attacks

Auto-generated from [`data/iocs.json`](data/iocs.json). To add a new attack family, see [CONTRIBUTING.md](docs/CONTRIBUTING.md).

| Attack family | First observed | Ecosystem | IoC class | Source |
|---|---|---|---|---|
| Shai-Hulud | 2025-09-15 | npm | package + file + process + github | [StepSecurity](https://www.stepsecurity.io/blog/) |
| chalk maintainer phish | 2025-09-08 | npm | package | [Snyk Advisory](https://security.snyk.io/) |
| SANDWORM_MODE | 2025-11-XX | npm | package + network | [Socket](https://socket.dev/blog) |
| Shai-Hulud 2.0 | 2025-12-XX | npm | package + file + process + github | [Microsoft](https://www.microsoft.com/en-us/security/blog/2025/12/09/shai-hulud-2-0-guidance-for-detecting-investigating-and-defending-against-the-supply-chain-attack/) |
| axios postinstall | 2026-03-12 | npm | package + network | [GHSA](https://github.com/advisories) |
| Mini Shai-Hulud (TanStack) | 2026-05-01 | npm | package | [StepSecurity](https://www.stepsecurity.io/blog/mini-shai-hulud-is-back-a-self-spreading-supply-chain-attack-hits-the-npm-ecosystem) |

Tracks **N attack families · N indicators · coverage window 2025-09-01 → present.** (Auto-updated every hour by the [aggregator workflow](.github/workflows/aggregator.yml).)

## Exit codes

For CI use. Same contract across all three modes.

```
0  Scan completed. Zero IoCs matched at any severity ≥ low. (Install passed through cleanly.)
1  Scan completed. ≥1 IoC matched at severity ≥ medium. (Install was blocked — postinstall did NOT run.)
2  Scanner error (network, parse, permission). Scan did not complete.
```

## If patient-zero flags something

Don't panic, don't revoke tokens yet. Read [`docs/RESPONSE.md`](docs/RESPONSE.md) first — it has per-attack-family triage steps.

**Critical caveat for Shai-Hulud family findings:** the `gh-token-monitor` daemon has a destructive failsafe. If patient-zero shows a Shai-Hulud finding, read [`docs/SHAI-HULUD-FAILSAFE.md`](docs/SHAI-HULUD-FAILSAFE.md) **before rotating any token**. The CLI will link you there directly when it triggers.

Example finding output:

```
[CRITICAL] 1 indicator matched: family=shai-hulud
  ↳ Read this before rotating any token: docs/SHAI-HULUD-FAILSAFE.md
[OK]       0 indicators matched: lockfiles, processes, github, mcp

Scanned 47 lockfiles · 234 processes · 12 MCP configs in 1.4s.
Coverage window: 2025-09-01 → present.
```

## How it works

patient-zero fetches a single normalized IoC list ([`data/iocs.json`](data/iocs.json)) from GitHub once per hour, then runs five scanners in parallel against your machine, lockfiles, and GitHub account (opt-in). It does not phone home, does not collect telemetry, does not require a signup. The IoC list and the source feeds it aggregates from are public.

The IoC list is updated hourly by a [GitHub Actions workflow](.github/workflows/aggregator.yml) that pulls from OSV.dev, GitHub Security Advisories, and a hand-curated [`data/manual-iocs.json`](data/manual-iocs.json). Source code: [`aggregator/`](aggregator/).

## CI usage

The composite action is the easiest way. It runs patient-zero, generates a SARIF report, and (combined with `github/codeql-action/upload-sarif`) populates the repo's Security tab inline with findings.

```yaml
- uses: 0xSteph/patient-zero@v0.2
  id: patient-zero
  with:
    ecosystem: npm           # optional: restrict to one ecosystem
    fail-on: medium          # critical|high|medium|low|info

- uses: github/codeql-action/upload-sarif@v4
  if: always()
  with:
    sarif_file: patient-zero.sarif
    category: patient-zero
```

If you don't want the action and prefer to call the CLI directly:

```yaml
- run: npx patient-zero@latest scan --no-github --json --sarif patient-zero.sarif > scan.json
- uses: github/codeql-action/upload-sarif@v4
  if: always()
  with:
    sarif_file: patient-zero.sarif
```

Both shapes produce SARIF v2.1.0 — GitHub's Security tab understands it natively.

## Contributing a new IoC

We curate `data/manual-iocs.json` for attack indicators that only appear in blog posts and incident writeups. PR template:

1. Read [`docs/IOC-SCHEMA.md`](docs/IOC-SCHEMA.md) for the field contract.
2. Add your entries to `data/manual-iocs.json`.
3. Open a PR with a one-line title: `add IoCs for <attack-family>` and a link to your source writeup.

A new attack family also needs an entry in `attack_families` and at minimum one external `primary_external_source`. We do not accept entries without an external source link.

[Full guide →](docs/CONTRIBUTING.md)

## Comparison

|                          | On-demand triage | Install-time block | CI / GH Action | Process / local scan | MCP-aware | Open IoC DB | Free, no signup |
|---|---|---|---|---|---|---|---|
| **patient-zero**         | ✓                | ✓                  | ✓ (SARIF)      | ✓                    | ✓         | ✓           | ✓               |
| [Aikido Safe Chain](https://github.com/AikidoSec/safe-chain) | ✓ | ✓ | ✓ | ✗ | ✗ | ✗ (closed) | ✓ |
| [Socket](https://socket.dev/) Free | ✓ | ✓ | ✓ | ✗ | ✗ | ✗ (closed) | ✗ (signup) |
| [osv-scanner](https://github.com/google/osv-scanner) | ✓ | ✗ | ✓ | ✗ | ✗ | ✓ | ✓ |
| [npq](https://github.com/lirantal/npq) | ✗ | ✓ | ✗ | ✗ | ✗ | ✓ | ✓ |
| Dependabot (GitHub native) | ✗ | ✗ | ✓ (only on GitHub) | ✗ | ✗ | ✓ | ✓ (GitHub only) |
| Snyk Open Source         | partial          | ✗                  | ✓              | ✗                    | ✗         | ✗           | ✗ (signup)      |
| [Cobenian/shai-hulud-detect](https://github.com/Cobenian/shai-hulud-detect) | ✓ | ✗ | ✗ | partial | ✗ | ✓ (1 family) | ✓ |

The lockfile-malware row got crowded after Dependabot added native malware alerts in March 2026. patient-zero's bet for differentiation is on the columns most competitors leave empty: **MCP / process / local persistence scanning, plus install-time blocking with an open IoC database**.

We work alongside the continuous tools — not as a replacement. If you have Snyk in CI, keep it. patient-zero is what you reach for the moment a new supply-chain attack disclosure hits the news, and what you wire into `npm install` to catch the attack before postinstall runs.

## Security disclosure

Found a vulnerability in patient-zero itself? See [`SECURITY.md`](SECURITY.md).

Reporting a malicious package or compromised MCP server you found in the wild? Open a PR adding it to `data/manual-iocs.json` (see Contributing above), or email the maintainer link in `SECURITY.md` if disclosure needs to be coordinated.

## License

MIT. See [`LICENSE`](LICENSE).

---

Maintained by [@0xSteph](https://github.com/0xSteph). Incident updates: [@patient_zero_cli](https://twitter.com/patient_zero_cli).
