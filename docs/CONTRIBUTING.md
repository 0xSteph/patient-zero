# Contributing to patient-zero

The most valuable thing you can contribute is **new IoCs**. The code is ~1,500 lines and rewriteable in a weekend; the IoC database is what makes this project useful, and it grows one PR at a time.

## Adding a new IoC

Most public IoCs (compromised package versions) come into our database automatically from OSV.dev and GitHub Security Advisories via the aggregator. You only need to PR an entry by hand if the IoC is something only published in a blog post — daemon names, file paths, MCP servers, GitHub repo patterns, network indicators.

### 1. Find your attack family

Open [`data/manual-iocs.json`](../data/manual-iocs.json) and check the `attack_families` block. If your attack already has an entry, skip to step 3.

### 2. Add a new attack family

```jsonc
"your-attack-family-key": {
  "display_name": "Human-readable name",
  "description": "1–3 sentences. What happened.",
  "first_observed": "YYYY-MM-DD",
  "ecosystems": ["npm"],
  "ioc_class_summary": "package + file",
  "primary_external_source": {
    "name": "Name of the firm or researcher who published the writeup",
    "url": "https://link-to-the-writeup"
  },
  "active_threat": true,
  "destructive_failsafe": false,
  "references": []
}
```

**`primary_external_source` is mandatory.** PRs without a verifiable external source link will not be merged. This is what makes our scope-claims trustworthy.

### 3. Add the indicators

Add entries to the `indicators` array in `data/manual-iocs.json`. See [`docs/IOC-SCHEMA.md`](IOC-SCHEMA.md) for the per-type field contract.

Example — a malicious MCP server:

```jsonc
{
  "id": "PZ-yourattack-mcp-001",
  "type": "mcp",
  "attack_family": "your-attack-family-key",
  "severity": "critical",
  "first_seen": "2026-XX-XX",
  "last_updated": "2026-XX-XX",
  "source": "manual",
  "description": "Brief description of what this MCP server does.",
  "references": ["https://writeup-url"],
  "mcp_server_names": ["@malicious/server-name"],
  "mcp_server_urls": ["https://attacker.example/mcp"],
  "config_path_patterns": [
    "~/.claude/mcp\\.json",
    "~/.cursor/mcp\\.json"
  ],
  "config_content_patterns": ["malicious/server-name"],
  "platforms": ["all"],
  "remediation": {
    "what_to_do": [
      "Remove the MCP server entry from your agent config",
      "Restart Claude Code / Cursor",
      "Audit recent agent sessions for unexpected tool access"
    ],
    "commands": ["claude mcp list"]
  }
}
```

### 4. Required-fields checklist

Before opening the PR, verify:

- [ ] `primary_external_source.url` resolves to a real published writeup
- [ ] `first_observed` matches the date in that writeup
- [ ] For severity `critical` or `high`: `remediation.what_to_do` has at least one item
- [ ] Indicator `id` is unique across the file
- [ ] `attack_family` matches a key that exists in the `attack_families` block

### 5. Open the PR

- PR title: `add IoCs for <attack-family-display-name>`
- PR body: one-paragraph summary + link to the writeup
- One PR per attack family is preferred; mixing families slows review

We aim to merge well-sourced IoC PRs within 48 hours. If your PR sits longer than 72 hours without comment, ping the maintainer.

## Reporting a false positive

If patient-zero flagged something that's verifiably benign:

1. Open a regular issue (not a PR).
2. Include: the IoC `id` that fired, the artifact it matched, the upstream source URL we cited.
3. We will remove or scope the IoC within 48 hours if the false positive is confirmed.

## Contributing code

Code contributions are welcome but lower priority than IoC contributions. If you want to work on code:

- Discuss the change in an issue first if it's larger than a one-file fix
- Match the existing style (modern ES modules, no build step, minimal deps)
- Add a test in `test/` for any new scanner logic
- All scanners must respect the [exit-code contract](../README.md#exit-codes)

## Code of conduct

This project follows the [Contributor Covenant](https://www.contributor-covenant.org/version/2/1/code_of_conduct/) v2.1. Be respectful. Disagreement is fine; personal attacks are not.

## Maintainers

- [@0xSteph](https://github.com/0xSteph) — project lead
