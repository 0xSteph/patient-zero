# If patient-zero flagged something

This page contains triage guidance per attack family. Find the family the CLI reported and follow its steps.

## Shai-Hulud and Shai-Hulud 2.0

These two families have a destructive failsafe. The standard "rotate tokens" reflex is dangerous here.

**Go directly to [SHAI-HULUD-FAILSAFE.md](SHAI-HULUD-FAILSAFE.md) before any other action.**

## chalk maintainer phish (September 2025)

A short-lived malicious version of chalk was published with a postinstall that exfiltrated environment variables.

**Triage:**

1. Run `npm ls chalk` in every project you maintain. Note any project pulling the flagged version.
2. Check if you ran `npm install` in any of those projects during the compromise window (approximately 2025-09-08 to 2025-09-12).
3. If yes: review which environment variables were set during the install. Most CI environments expose tokens via env vars.
4. Rotate any tokens that were in the environment during the install: GitHub Actions secrets, npm tokens, cloud provider keys, anything else in env.
5. Pin chalk to a known-clean version in your lockfile.

The compromise window is brief — most installs after 2025-09-12 should be safe, but verify by checking your lockfile against the IoC.

## SANDWORM_MODE

Campaign of packages containing an obfuscated postinstall script identifiable by the string `SANDWORM_MODE` in the bundle.

**Triage:**

1. Identify which lockfile pulled the flagged package.
2. Search the installed `node_modules` for the string: `grep -r SANDWORM_MODE node_modules/<package>/`. Confirm the indicator.
3. The exfiltration channel is a network call. Check outbound network logs from the install host for unusual DNS/HTTP traffic during the install window.
4. Rotate any tokens that were in the environment.
5. Remove the compromised version and pin to a known-clean version.

## axios postinstall (March 2026)

A brief window (~6 hours) where a malicious axios version was on the registry. Postinstall exfiltrated env vars via DNS.

**Triage:**

1. Check the date you last ran `npm install` against any project pulling axios.
2. If the install timestamp falls within March 12–13, 2026: assume environment variables were exfiltrated.
3. Rotate any tokens that were set during that install window.
4. Pin axios to the known-clean version specified in the IoC entry.

## Mini Shai-Hulud (TanStack, May 2026)

Self-spreading worm variant in the TanStack ecosystem. No persistence daemon observed — this is the most important difference from Shai-Hulud 1.0/2.0.

**Triage:**

1. Standard supply-chain incident response applies (no destructive failsafe to worry about).
2. Audit your maintainer accounts on npm for unexpected published versions.
3. Audit your GitHub account for unexpected new repos.
4. Rotate npm and GitHub tokens.
5. Pin all affected TanStack packages to versions before the compromise window.

## Generic guidance — when in doubt

If a finding doesn't match a family above:

1. Read the `description` and `references` URLs in the CLI output. Each indicator includes a link to a writeup.
2. Determine the compromise window (date the malicious version was on the registry / when the IoC was first observed).
3. Determine whether you installed during that window. If unsure, assume yes.
4. Rotate credentials that were in the environment during that window.
5. Pin to a known-clean version.

If you can't find a writeup link, the entry is malformed; please [file an issue](https://github.com/0xSteph/patient-zero/issues).
