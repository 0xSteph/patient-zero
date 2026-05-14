# Security Policy

## Reporting a vulnerability in patient-zero

If you find a vulnerability in this tool itself (the CLI, the aggregator, or our IoC data integrity), please report it privately first:

- Open a [GitHub Security Advisory](https://github.com/0xSteph/patient-zero/security/advisories/new) on this repo. This is the preferred channel.
- Or email the maintainer using the email listed on the [GitHub profile](https://github.com/0xSteph). Mention "patient-zero security" in the subject line.

We aim to acknowledge reports within 72 hours and to publish a fix or mitigation within 14 days for high-severity issues.

## Reporting a false positive

If patient-zero flagged a package or pattern that you've verified is benign:

1. Open a regular GitHub Issue (not a security advisory).
2. Include: the IoC ID that fired, the artifact it matched, and a link to the upstream source we cited.
3. We will remove or scope the entry within 48 hours if the false positive is confirmed.

## Reporting a new supply-chain attack you discovered

If you found a malicious package, MCP server, or compromised maintainer account and want it added to our IoC database:

- Open a regular Pull Request adding entries to [`data/manual-iocs.json`](data/manual-iocs.json).
- See [`docs/CONTRIBUTING.md`](docs/CONTRIBUTING.md) for the schema and PR template.
- Every entry requires a `primary_external_source` link to a published writeup. We do not accept anonymous or unsourced entries.

If the attack is unpublished and disclosure needs to be coordinated, email the maintainer directly first; we will help time the public IoC publication with the disclosure.

## What this tool does NOT defend against

patient-zero is a detection-and-triage tool. It does not:

- Block malicious installs (use Aikido Safe Chain or similar for that)
- Provide continuous monitoring (use Snyk, Socket, or osv-scanner in CI)
- Remediate compromised systems
- Replace incident-response procedures

Read [`docs/RESPONSE.md`](docs/RESPONSE.md) for what to do after a positive finding.
