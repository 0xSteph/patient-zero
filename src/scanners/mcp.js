import { readFile } from 'node:fs/promises';
import { homedir } from 'node:os';
import path from 'node:path';

/**
 * Known AI-agent MCP config locations across tools and platforms.
 * Each entry is a candidate absolute path (after ~ expansion).
 */
function defaultConfigPaths() {
  const home = homedir();
  return [
    // Claude Desktop
    path.join(home, 'Library/Application Support/Claude/claude_desktop_config.json'),
    path.join(home, '.config/Claude/claude_desktop_config.json'),
    // Claude Code — settings + per-user MCP config
    path.join(home, '.claude.json'),
    path.join(home, '.claude/mcp.json'),
    path.join(home, '.claude/settings.json'),
    // Cursor
    path.join(home, '.cursor/mcp.json'),
    // Cline
    path.join(home, '.config/cline/mcp_settings.json'),
    path.join(home, 'Library/Application Support/cline/mcp_settings.json'),
  ];
}

/**
 * Scan AI-agent MCP server configurations for known-malicious entries.
 *
 * @param {Object} iocs
 * @param {{ configPaths?: string[] }} [options]
 * @returns {Promise<{ findings: Array, scanned: { configs_found: number, configs_parsed: number }, errors: string[] }>}
 */
export async function scan(iocs, options = {}) {
  const paths = options.configPaths ?? defaultConfigPaths();
  const mcpIndicators = iocs?.indicators?.mcp ?? [];
  const findings = [];
  const errors = [];
  let configsFound = 0;
  let configsParsed = 0;

  for (const filePath of paths) {
    let raw;
    try {
      raw = await readFile(filePath, 'utf8');
    } catch {
      continue; // file doesn't exist, normal
    }
    configsFound += 1;

    let doc;
    try {
      doc = JSON.parse(raw);
      configsParsed += 1;
    } catch (err) {
      errors.push(`failed to parse ${filePath}: ${err.message}`);
      continue;
    }

    const serverEntries = extractMcpServers(doc);

    for (const indicator of mcpIndicators) {
      const nameSet = new Set((indicator.mcp_server_names ?? []).map((s) => s.toLowerCase()));
      const urlSet = new Set((indicator.mcp_server_urls ?? []).map((s) => s.toLowerCase()));
      const contentPatterns = (indicator.config_content_patterns ?? []).map((p) => safeRegex(p));

      for (const { name, command, args, url } of serverEntries) {
        const reasons = [];
        if (name && nameSet.has(name.toLowerCase())) reasons.push(`server name "${name}"`);
        if (url && urlSet.has(url.toLowerCase())) reasons.push(`server url "${url}"`);

        const joined = [name, command, ...(args ?? []), url].filter(Boolean).join(' ');
        for (const re of contentPatterns) {
          if (re && re.test(joined)) reasons.push(`content matches /${re.source}/`);
        }

        if (reasons.length > 0) {
          findings.push({
            indicator,
            artifact: { config: filePath, server: name ?? '(unnamed)', url: url ?? null, reasons },
          });
        }
      }

      // Also check raw content patterns against the entire file body
      if (serverEntries.length === 0) {
        for (const re of contentPatterns) {
          if (re && re.test(raw)) {
            findings.push({
              indicator,
              artifact: { config: filePath, server: '(raw-content match)', url: null, reasons: [`content matches /${re.source}/`] },
            });
          }
        }
      }
    }
  }

  return {
    findings,
    scanned: { configs_found: configsFound, configs_parsed: configsParsed },
    errors,
  };
}

/**
 * Extract a flat list of MCP server entries from a parsed config document.
 * Handles several known shapes:
 *   { mcpServers: { name: { command, args, url } } }                  ← Claude Desktop / Code
 *   { mcp: { servers: [{ name, command, args, url }] } }              ← Cursor
 *   { mcpServers: [{ name, command, args, url }] }                    ← Cline (some versions)
 */
function extractMcpServers(doc) {
  const out = [];

  if (doc && doc.mcpServers && typeof doc.mcpServers === 'object') {
    if (Array.isArray(doc.mcpServers)) {
      for (const s of doc.mcpServers) {
        if (s && typeof s === 'object') {
          out.push({ name: s.name, command: s.command, args: s.args, url: s.url });
        }
      }
    } else {
      for (const [name, s] of Object.entries(doc.mcpServers)) {
        if (s && typeof s === 'object') {
          out.push({ name, command: s.command, args: s.args, url: s.url });
        }
      }
    }
  }

  if (doc && doc.mcp && doc.mcp.servers && Array.isArray(doc.mcp.servers)) {
    for (const s of doc.mcp.servers) {
      if (s && typeof s === 'object') {
        out.push({ name: s.name, command: s.command, args: s.args, url: s.url });
      }
    }
  }

  return out;
}

function safeRegex(pattern) {
  try {
    return new RegExp(pattern);
  } catch {
    return null;
  }
}
