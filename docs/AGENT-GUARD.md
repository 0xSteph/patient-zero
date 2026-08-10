# Agent guard: `patient-zero protect`

`npx patient-zero protect` wires patient-zero into AI coding agents so package
installs the agent runs are scanned **before they execute** — including in auto
mode (`--dangerously-skip-permissions`, Cursor auto-run), where no human ever
sees the install command.

## Why this exists

AI agents install dependencies on your behalf. The verification window shrank
from "a human reads the package name" to "nothing reads it," and attackers
noticed: slopsquatting registers the package names LLMs hallucinate
(~19.7% of AI-recommended packages don't exist per the USENIX 2025 study), and
the July 2026 HalluSquatting research showed those hallucinations are
*predictable* enough to pre-register at scale. Meanwhile classic campaigns
(Shai-Hulud, chalk phish) ship malware in postinstall scripts that run the
moment the install does.

The guard is a deterministic hook — not advice in a rules file the model can
ignore. The agent literally cannot run the install without the guard's verdict.

## Supported agents

| Agent | Mechanism | Config touched |
|---|---|---|
| Claude Code | `PreToolUse` hook, matcher `Bash` | `~/.claude/settings.json` (or `./.claude/settings.json` with `--project`) |
| Cursor | `beforeShellExecution` hook | `~/.cursor/hooks.json` (or `./.cursor/hooks.json` with `--project`) |

`protect` detects which agents exist and installs for all of them; restrict
with `--agent claude-code` / `--agent cursor`. Edits are marker-identified,
idempotent, never touch entries we didn't create, and are fully reversed by
`npx patient-zero protect --remove`.

## What the guard checks

For every shell command the agent proposes, the guard parses out install
operations (`npm|pnpm|yarn|bun install/add`, `npx`/`dlx`/`bunx`,
`pip|pip3|pipx install`, `uv add`, `uv pip install`, `poetry add` — including
chained commands like `cd app && npm i evil`). Non-install commands are allowed
immediately with no network access. Install operations get four checks:

1. **IoC match** — requested packages against the same attack-campaign database
   every other patient-zero mode uses. Severity ≥ medium denies.
2. **Nonexistent package** (high) — a 404 from the registry means the name was
   likely hallucinated by an LLM. The deny reason tells the agent *not* to retry
   spelling variants — that's how slopsquats get installed.
3. **Lookalike name** (high) — within one edit (including transposition) of a
   popular package, or a popular name with a `js`/`node-` affix. Works offline
   against a bundled top-package list ([`data/popular-packages.json`](../data/popular-packages.json)).
4. **Release cooldown** (high) — the target version was published inside the
   cooldown window (default 48h, `--cooldown <hours>`). The deny reason names
   the previous stable version so the agent can install that instead.

Plus an informational signal: packages with `preinstall`/`install`/`postinstall`
scripts are noted but never block on their own.

## Design guarantees

- **Fail open.** Registry timeout, malformed payload, internal error → allow,
  with a note on stderr. A security hook that bricks dev loops gets uninstalled;
  one that quietly degrades keeps protecting everything else.
- **Fast path for non-installs.** The IoC database and registry are only
  consulted when the command actually installs something.
- **Actionable denials.** Deny reasons are written for the agent: what was
  blocked, why, and what to do instead ("install `chalk@5.6.2`", "did you mean
  `lodash`?"). Agents self-correct instead of stalling.
- **Explicit bypass.** If the user really wants the package, they run the
  install themselves in a terminal — the guard only governs the agent.

## Testing it

```sh
# should deny (lookalike):
echo '{"tool_name":"Bash","tool_input":{"command":"npm install lodahs"}}' \
  | npx patient-zero guard --agent claude-code

# should allow:
echo '{"tool_name":"Bash","tool_input":{"command":"npm install express@4.18.2"}}' \
  | npx patient-zero guard --agent claude-code
```

## Limitations

- The guard checks the *requested* packages, not the full transitive tree (the
  `patient-zero install` command does tree resolution; running it inside a hook
  would add ~10s to every install). A compromised transitive dependency with a
  clean top-level name passes the guard but is caught by `patient-zero install`,
  the pre-commit hook, and CI scans.
- Gemini CLI / Codex CLI hooks aren't wired yet.
- A determined user (or prompt-injected agent with settings-file write access)
  can remove the hook; this is a seatbelt, not a sandbox.
