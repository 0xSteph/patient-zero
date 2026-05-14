# MCP supply-chain IoCs — what to look for, how to contribute

MCP (Model Context Protocol) servers are a fresh attack surface as of 2025–2026. Each MCP server is essentially an installable package — typically published to npm or PyPI — that an AI agent (Claude Desktop, Claude Code, Cursor, Cline, Continue, etc.) executes on your behalf with permission to call its tools. Compromising an MCP server gives an attacker direct, agent-mediated access to your filesystem, terminal, browser, or whatever capability that server advertises.

patient-zero is the only free, no-execution scanner targeting this layer today. Snyk's `agent-scan` is the only mainstream alternative; it requires a token *and executes* the servers it scans, which is its own risk surface. We don't execute anything — we match config files against a normalized IoC database.

## What patient-zero scans

`src/scanners/mcp.js` reads:

- `~/Library/Application Support/Claude/claude_desktop_config.json` (Claude Desktop, macOS)
- `~/.config/Claude/claude_desktop_config.json` (Claude Desktop, Linux)
- `~/.claude.json`, `~/.claude/mcp.json`, `~/.claude/settings.json` (Claude Code)
- `~/.cursor/mcp.json` (Cursor)
- `~/.config/cline/mcp_settings.json` (Cline)
- `~/Library/Application Support/cline/mcp_settings.json` (Cline, macOS)

For each, it extracts the configured MCP server entries (name, command, args, url) and matches against IoC indicators of `type: "mcp"`. See [`docs/IOC-SCHEMA.md`](IOC-SCHEMA.md) for the per-field contract.

## What makes a good MCP IoC

| Quality | Threshold |
|---|---|
| **Confirmed-malicious** with a published writeup | `severity: critical`, real `primary_external_source` URL, expect a fast merge |
| **Strongly suspicious** but not yet confirmed | `severity: high` or `medium`, citation to the most recent published research |
| **Heuristic pattern** (typosquat, non-HTTPS URL, sensitive env var in config) | `severity: low`, point `primary_external_source` at this guide or a defensible documentary source |
| **"Probably legit but worth a heads-up"** | `severity: info`, expect pushback — most info-level entries don't ship |

Like every entry in patient-zero, MCP IoCs must cite an external source. We do not accept anonymous or unsourced entries even at low severity. If you discovered something new and want it added before publishing the writeup, email the maintainer (see [`SECURITY.md`](../SECURITY.md)) — we will coordinate disclosure.

## Patterns to watch for (the heuristic family)

These are the categories most commonly seen in MCP supply-chain attacks across npm and adjacent ecosystems. Patient-zero's `mcp-heuristics` attack family seeds the first few; community PRs are the path to coverage.

### 1. Typosquat of an official MCP package

`@modelcontextprotocol/server-filesystem` is the official Anthropic-published filesystem server. Names like `@modelcontextprotocols/server-filesystem` (note the plural), `@modelcontextprotocl/...` (dropped letter), or `@modelcontextprotocol-helper/...` (subdomain-style impersonation) are not official and have been observed as attack vectors for typosquatting.

### 2. Non-HTTPS MCP server URL in remote-server config

A `"url": "http://..."` (not `https://`) in an MCP server config means traffic is unencrypted and tamperable. There is no legitimate reason for an MCP server to use plaintext HTTP. Treat any such config as suspicious.

### 3. Sensitive credentials in MCP server `env` block

If an MCP server's config includes `env: { GITHUB_TOKEN, NPM_TOKEN, OPENAI_API_KEY, AWS_SECRET_ACCESS_KEY, ... }`, the user has handed a full credential to the server's process. This can be legitimate (e.g., a GitHub MCP server *needs* GITHUB_TOKEN), but it's worth surfacing — a compromised version of that server would have direct access to the token.

### 4. MCP server installed from an unusual registry

Configs that point at `"command": "npx -y <pkg>"` where `<pkg>` comes from a registry override (`.npmrc` pointing at a non-default registry) are higher risk. We don't have a high-confidence pattern for this yet — contributions welcome.

### 5. MCP server using a deprecated / pre-release version of an official server

Less obviously malicious, but legacy versions of even legitimate servers often have known issues. Flagging stale pins is informational, not a security alert.

## How to PR a new MCP IoC

1. Read [`docs/CONTRIBUTING.md`](CONTRIBUTING.md) for the schema.
2. Add to `data/manual-iocs.json`:
   - A new `attack_families[<key>]` if your finding represents a named incident.
   - One or more indicators of `type: "mcp"`.
3. Make sure each indicator has:
   - `mcp_server_names` (regex matched against the entry's name key)
   - `mcp_server_urls` (regex matched against `url`)
   - `config_content_patterns` (regex matched against the full config file content)
   - At least one of the above filled. Otherwise it can't match anything.
4. Open the PR with title `add MCP IoCs for <attack-family-name>`.

## What this guide is not

It is not exhaustive — MCP security is a fresh enough area that new patterns emerge faster than guides can keep up. It is not authoritative — the moment a regulator, vendor, or researcher publishes a more comprehensive guide for AI-agent supply chains, link out from here.

For now, this is the contributor playbook. Use the patterns above as a starting point; add your own findings via PR.
