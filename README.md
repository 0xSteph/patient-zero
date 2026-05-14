# patient-zero

Scans Node, Python, and AI-agent configs for indicators of compromise from npm and PyPI supply-chain attacks (Sept 2025 – present).

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

## Install

```sh
npx patient-zero@latest
```

That's it. No global install, no signup, no config. Runs against the current directory.

Pin a version in CI:

```sh
npx patient-zero@0.1.0
```

## What it scans

- npm lockfiles: `package-lock.json`, `pnpm-lock.yaml`, `yarn.lock`
- Python lockfiles: `requirements.txt`, `poetry.lock`
- Running processes (by name)
- Local persistence: `~/Library/LaunchAgents/` (macOS), `~/.config/systemd/user/` (Linux)
- Registry config: `~/.npmrc`, `~/.pypirc`
- AI-agent configs: Claude Desktop, Claude Code, Cursor, Cline (MCP server entries)
- Your GitHub account (opt-in, uses `gh` CLI or a PAT you provide)

[See the full IoC list →](data/iocs.json) · [Schema →](docs/IOC-SCHEMA.md)

## What this is NOT

- Not an EDR. Not a runtime sandbox.
- Not a continuous CI scanner. That's Snyk, Socket, Aikido, osv-scanner. They run 24/7.
- Not a Snyk replacement. Different job.

patient-zero is the first-aid kit you grab when a supply-chain attack hits the news. 30 seconds, zero install, then you go back to work.

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

For CI use.

```
0  Scan completed. Zero IoCs matched at any severity ≥ low.
1  Scan completed. ≥1 IoC matched at severity ≥ medium.
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

GitHub Actions:

```yaml
- name: Supply-chain triage
  run: npx patient-zero@0.1.0 --json --no-github > patient-zero.json
  continue-on-error: false   # exit 1 = finding; exit 2 = scanner error
```

`--json` produces machine-parseable output. `--no-github` skips the GitHub account scan in CI environments where `gh` isn't authenticated.

## Contributing a new IoC

We curate `data/manual-iocs.json` for attack indicators that only appear in blog posts and incident writeups. PR template:

1. Read [`docs/IOC-SCHEMA.md`](docs/IOC-SCHEMA.md) for the field contract.
2. Add your entries to `data/manual-iocs.json`.
3. Open a PR with a one-line title: `add IoCs for <attack-family>` and a link to your source writeup.

A new attack family also needs an entry in `attack_families` and at minimum one external `primary_external_source`. We do not accept entries without an external source link.

[Full guide →](docs/CONTRIBUTING.md)

## Comparison

|                          | Continuous? | Multi-family? | MCP-aware? | Zero-install? | Free forever? |
|---|---|---|---|---|---|
| **patient-zero**         | No          | Yes           | **Yes**    | **Yes**       | **Yes**       |
| [Cobenian/shai-hulud-detect](https://github.com/Cobenian/shai-hulud-detect) | No | 1 family | No | No (clone) | Yes |
| [osv-scanner](https://github.com/google/osv-scanner) | Yes (CI) | Yes | No | No (install) | Yes |
| Snyk Open Source         | Yes (CI)    | Yes           | No         | No (signup)   | Free tier     |
| [Aikido Safe Chain](https://github.com/AikidoSec/safe-chain) | Yes (install) | Yes | No | No (install) | Free tier |

Different tools, different jobs. The continuous scanners catch things in your daily pipeline. patient-zero is what you reach for in the 30 seconds after a new supply-chain attack hits the news.

## Security disclosure

Found a vulnerability in patient-zero itself? See [`SECURITY.md`](SECURITY.md).

Reporting a malicious package or compromised MCP server you found in the wild? Open a PR adding it to `data/manual-iocs.json` (see Contributing above), or email the maintainer link in `SECURITY.md` if disclosure needs to be coordinated.

## License

MIT. See [`LICENSE`](LICENSE).

---

Maintained by [@0xSteph](https://github.com/0xSteph). Incident updates: [@patient_zero_cli](https://twitter.com/patient_zero_cli).
