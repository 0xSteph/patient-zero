# IoC schema reference (v1.0)

This is the contract for entries in `data/manual-iocs.json` and the format the aggregator produces in `data/iocs.json`. The schema is versioned; breaking changes get a major version bump and the CLI checks compatibility on load.

## Top-level shape

```json
{
  "schema_version": "1.0",
  "generated_at": "2026-05-14T18:00:00Z",
  "coverage_window": { "start": "2025-09-01", "end": "present" },
  "attack_family_count": 6,
  "indicator_count": 3,
  "generator": { "name": "patient-zero-aggregator", "version": "0.1.0", "run_id": "..." },
  "sources": [
    { "name": "osv-npm", "fetched_at": "...", "indicator_count": 0, "status": "ok" },
    { "name": "osv-pypi", "fetched_at": "...", "indicator_count": 0, "status": "ok" },
    { "name": "github-advisories", "fetched_at": "...", "indicator_count": 0, "status": "ok" },
    { "name": "manual", "fetched_at": "...", "indicator_count": 3, "status": "ok" }
  ],
  "attack_families": { /* keyed map */ },
  "indicators": {
    "package": [],
    "file": [],
    "process": [],
    "github": [],
    "network": [],
    "mcp": []
  },
  "indexes": {
    "packages_by_ecosystem_name": {}
  }
}
```

For `data/manual-iocs.json` specifically, `indicators` is a **flat array** (the aggregator regroups by type). Contributors don't need to know the grouped shape — just write entries with a `type` field and the aggregator handles the rest.

## Attack family

```jsonc
{
  "id-key": {                                    // key used by indicators' attack_family field
    "display_name": "Human-readable name",
    "description": "1–3 sentences. What this campaign is.",
    "first_observed": "YYYY-MM-DD",              // verified against primary_external_source
    "ecosystems": ["npm", "pypi", ...],
    "ioc_class_summary": "package + file + ...", // for the public attacks table
    "primary_external_source": {
      "name": "StepSecurity",                    // who published the writeup
      "url": "https://..."                       // the writeup URL — REQUIRED
    },
    "active_threat": true,                       // false once patched/withdrawn
    "destructive_failsafe": false,               // true triggers the red-banner warning
    "failsafe_warning": "Optional explicit warning text shown when destructive_failsafe=true",
    "references": ["https://..."]                // additional reading
  }
}
```

`primary_external_source` is mandatory. Entries without it are rejected by the aggregator.

## Indicator — common fields

Every indicator regardless of type has these fields:

```jsonc
{
  "id": "GHSA-xxxx-yyyy-zzzz",   // upstream ID if available; else PZ-<family>-<n>
  "type": "package|file|process|github|network|mcp",
  "attack_family": "shai-hulud", // must match a key in attack_families
  "severity": "critical|high|medium|low|info",
  "first_seen": "YYYY-MM-DD",
  "last_updated": "YYYY-MM-DD",
  "source": "osv-npm|osv-pypi|github-advisories|openssf-malicious|manual",
  "references": ["https://..."],
  "description": "What this is and what to do, in 1–2 sentences.",
  "remediation": {                // REQUIRED on severity=critical|high
    "what_to_do": ["step 1", "step 2"],
    "commands": ["specific commands the user can run"]
  }
}
```

### Required-fields rule

For severity `critical` or `high`, the `remediation` block is **required** and must contain at least one item in `what_to_do`. The aggregator rejects entries that violate this rule. We do not ship critical-severity findings with no operator guidance.

## Indicator — per-type extra fields

### `type: "package"`

```jsonc
{
  /* ...common fields... */
  "ecosystem": "npm|pypi|rubygems|crates|maven|go|nuget",
  "name": "package-name",
  "versions": "5.3.1",                  // ecosystem-native range syntax
  "version_range": "exact|semver|pep440",
  "withdrawn": "2025-09-08T14:23:00Z",  // optional: when withdrawn from registry
  "advisory_id": "GHSA-..."             // optional: upstream advisory
}
```

The `versions` field uses native syntax per ecosystem. `npm` uses semver (`>=1.2.3 <1.3.0`); `pypi` uses PEP 440 (`>=1.2.3,<1.3.0`). The scanner picks the right parser based on `ecosystem`.

Index keys (`packages_by_ecosystem_name`) are always **lowercase** since npm is case-insensitive and PyPI normalizes.

### `type: "file"`

```jsonc
{
  /* ...common fields... */
  "path_patterns": ["regex"],           // anchored regex, matched against absolute paths
  "content_patterns": ["regex"],        // optional in v0.1 (v0.2 implements content scanning)
  "sha256": ["hex"],                    // optional: known-bad file hashes
  "platforms": ["darwin", "linux", "win32", "all"]
}
```

`~` in patterns is expanded to the user's home directory at scan time. Patterns are matched case-sensitively unless you explicitly include the `(?i)` flag.

### `type: "process"`

```jsonc
{
  /* ...common fields... */
  "process_names": ["exact-name"],
  "command_patterns": ["regex"],        // optional in v0.1
  "platforms": ["darwin", "linux", "win32", "all"]
}
```

### `type: "github"`

```jsonc
{
  /* ...common fields... */
  "repo_name_patterns": ["regex"],
  "repo_description_patterns": ["regex"],
  "commit_message_patterns": ["regex"],
  "scope": "user-repos"                 // v0.1 only supports user-repos
}
```

### `type: "network"`

```jsonc
{
  /* ...common fields... */
  "domains": ["evil.example"],
  "ips": ["1.2.3.4"],
  "url_patterns": ["regex"],
  "context": "Where this would appear (e.g. 'npmrc registry override', 'postinstall fetch')"
}
```

### `type: "mcp"`

```jsonc
{
  /* ...common fields... */
  "mcp_server_names": ["@malicious/mcp-server"],
  "mcp_server_urls": ["https://evil.example/mcp"],
  "config_path_patterns": ["~/.claude/mcp\\.json", "~/.cursor/mcp\\.json"],
  "config_content_patterns": ["regex"],
  "platforms": ["all"]
}
```

The MCP scanner matches both the path patterns (looking for the config file) and the content patterns (matching server names / URLs inside the JSON). v0.1 supports Claude Desktop, Claude Code, Cursor, and Cline config formats.

## Aggregator-generated fields

These exist in `data/iocs.json` but are NOT written by contributors; the aggregator produces them:

- `coverage_window`: derived from min/max of all `first_observed` dates
- `attack_family_count`, `indicator_count`: counts
- `generated_at`, `generator.run_id`: build metadata
- `sources[].fetched_at`, `sources[].status`: per-source health
- `indexes.packages_by_ecosystem_name`: precomputed lookup for the lockfile scanner

## Schema versioning

`schema_version` is semver-shaped (`major.minor`). The CLI refuses to load a file with a different `major` than it supports. Minor bumps are additive only — new optional fields, never removed or repurposed fields.

When in doubt about whether a change is breaking, treat it as breaking and bump major.
