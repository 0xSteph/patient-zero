# patient-zero

**Vibe code without getting infected.** Your AI agent installs packages you never see — patient-zero is the hook it can't skip. One command wires it into Claude Code and Cursor so every install the agent runs (even in auto / skip-permissions mode) is checked for known supply-chain malware, hallucinated package names, and day-zero uploads *before* any install script executes.

Also: triage your machine in 30 seconds when an attack hits the news, block malicious installs at the command line, or wire it into CI — same IoC database, one command, no signup.

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
0.02s · coverage 2025-09-08 → present · 7 families · 6 indicators · IoC: fresh
```

<details><summary>Or watch the 12-second animated demo</summary>

![demo](docs/assets/demo.gif)

</details>

## Four ways to use it

### 1. Protect your AI agent — the one prompt it can't skip

```sh
npx patient-zero@latest protect
```

Detects Claude Code and Cursor on your machine and installs patient-zero as an agent hook (Claude Code `PreToolUse`, Cursor `beforeShellExecution`). From then on, every install command the agent runs — `npm`/`pnpm`/`yarn`/`bun`/`npx` and `pip`/`uv`/`poetry`/`pipx` — is intercepted and checked **before it executes**, even when the agent runs in auto mode with permission prompts disabled:

- **Known IoCs** — the same attack-campaign database all other modes use.
- **Hallucinated packages** — the requested package doesn't exist on the registry: the exact pattern [slopsquatting](https://www.endorlabs.com/learn/slopsquatting-when-ai-agents-hallucinate-malicious-packages) attacks exploit. Research on LLM package hallucination found ~19.7% of AI-recommended packages don't exist.
- **Lookalike names** — one edit away from a popular package (`lodahs`, `expressjs`).
- **Release cooldown** — the version was published under 48h ago. Most supply-chain malware is caught within days of upload; cooldown users were protected from the Shai-Hulud campaigns before public advisories existed. patient-zero suggests the previous stable version, and the agent installs that instead.

Denials return a machine-readable reason, so the agent self-corrects ("install `chalk@5.6.2` instead") rather than just failing. Guards fail open — a broken network or scanner bug never bricks your dev loop. Remove anytime with `npx patient-zero protect --remove`.

### 2. On-demand triage — when the news breaks

```sh
npx patient-zero@latest
```

No global install, no signup, no config. Runs against the current directory. Use this when chalk / axios / the latest Shai-Hulud variant hits Hacker News and you need a fast yes/no on whether your machine is affected.

### 3. Install-time blocking — catch malware *before* it runs

```sh
npx patient-zero@latest install <package>
```

Resolves the proposed install tree in a sandboxed temp directory, cross-references every transitive dependency against the IoC database, and refuses to proceed if any indicator matches. **Postinstall scripts never execute.** This is the most valuable single feature for the agent era — your AI agent installs things on your behalf; you don't see every install; this catches it.

### 4. Continuous CI — every commit, every PR

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
| SANDWORM_MODE | 2025-11-01 | npm | package + network | [Socket](https://socket.dev/blog) |
| Shai-Hulud 2.0 | 2025-12-09 | npm | package + file + process + github | [Microsoft](https://www.microsoft.com/en-us/security/blog/2025/12/09/shai-hulud-2-0-guidance-for-detecting-investigating-and-defending-against-the-supply-chain-attack/) |
| axios postinstall | 2026-03-12 | npm | package + network | [GHSA](https://github.com/advisories) |
| Mini Shai-Hulud (TanStack) | 2026-05-01 | npm | package | [StepSecurity](https://www.stepsecurity.io/blog/mini-shai-hulud-is-back-a-self-spreading-supply-chain-attack-hits-the-npm-ecosystem) |

Tracks **6 named attack campaigns + the full OSV/OpenSSF malicious-packages feed (rolling 30-day window, ~3,500 package indicators) + 1 heuristic family (MCP supply-chain patterns) · coverage window 2025-09-08 → present.** Auto-updated every hour by the [aggregator workflow](.github/workflows/aggregator.yml) — see [docs/ATTACKS.md](docs/ATTACKS.md) for live counts. Malware older than the rolling window is still caught at install time by the live OSV.dev lookup in the guard and interceptor.

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
Coverage window: 2025-09-08 → present.
```

## How it works

patient-zero fetches a single normalized IoC list ([`data/iocs.json`](data/iocs.json)) from GitHub once per hour, then runs five scanners in parallel against your machine, lockfiles, and GitHub account (opt-in). Install-time paths (the agent guard and `patient-zero install`) additionally query OSV.dev live for the exact packages being installed, covering the full 200k+ entry malicious-packages corpus without bundling it. It does not phone home, does not collect telemetry, does not require a signup. The IoC list and the source feeds it aggregates from are public.

The IoC list is updated hourly by a [GitHub Actions workflow](.github/workflows/aggregator.yml) that pulls the OSV.dev bulk feeds (npm + PyPI, MAL-* advisories from [OpenSSF malicious-packages](https://github.com/ossf/malicious-packages), rolling 30-day window) and merges a hand-curated [`data/manual-iocs.json`](data/manual-iocs.json). Source code: [`aggregator/`](aggregator/).

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

The lockfile-malware row got crowded after Dependabot added native malware alerts in March 2026. patient-zero's bet for differentiation is on the columns most competitors leave empty: **agent-hook protection (Claude Code / Cursor installs checked in-flight), slopsquat + cooldown heuristics, MCP / process / local persistence scanning, plus install-time blocking with an open IoC database**.

We work alongside the continuous tools — not as a replacement. If you have Snyk in CI, keep it. patient-zero is what you reach for the moment a new supply-chain attack disclosure hits the news, and what you wire into `npm install` to catch the attack before postinstall runs.

## Security disclosure

Found a vulnerability in patient-zero itself? See [`SECURITY.md`](SECURITY.md).

Reporting a malicious package or compromised MCP server you found in the wild? Open a PR adding it to `data/manual-iocs.json` (see Contributing above), or email the maintainer link in `SECURITY.md` if disclosure needs to be coordinated.

## License

MIT. See [`LICENSE`](LICENSE).

---

Maintained by [@0xSteph](https://github.com/0xSteph). Incident updates: [@patientzerocli](https://twitter.com/patientzerocli).
