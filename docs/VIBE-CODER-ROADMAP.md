# Product research: making patient-zero the default seatbelt for vibe coding

*Research date: 2026-08-10. Status: proposal, not yet scheduled.*

## The question we started from

> "Is it still true that AI agents infect machines by auto-installing things when people
> run them in auto mode?"

**Yes — and the problem got worse in 2026, not better.** Evidence:

- **Agents still auto-install with no human in the loop.** YOLO-style flags
  (`--dangerously-skip-permissions`, `--yolo`, `--trust-all-tools`) remain widely used.
  Even Claude Code's improved auto mode (March 2026) auto-clears the ~93% of prompts users
  approve anyway — an `npm install` of a plausible-looking package is exactly the kind of
  call that sails through. The verification window shrank from "a human reads the package
  name" to "nothing reads it."
- **Slopsquatting is measurably real.** The USENIX 2025 package-hallucination study found
  **19.7% of LLM-recommended packages don't exist** (205,000+ unique fake names). Attackers
  register the high-probability hallucinations and wait.
- **HalluSquatting (disclosed July 2026)** industrialized this: researchers at Tel Aviv
  University and Technion showed attackers can *predict* which fake package/repo/skill names
  a model will hallucinate, pre-register them, and achieve **85–100% hit rates** in
  repo-cloning and skill-installation scenarios — no prompt injection or access to the
  victim needed.
- **Attackers already target agent machines specifically.** The Nx "s1ngularity" compromise
  (Aug 2025) shipped payloads that checked whether Claude Code, Gemini CLI, or Amazon Q were
  installed. Shai-Hulud 2.0 (Dec 2025) and Mini Shai-Hulud (May 2026) continued the pattern.

So the market thesis holds: **the population most exposed to supply-chain malware is now
people who don't read their installs — vibe coders.** They are also the population least
likely to sign up for Snyk. That's our lane.

## Gap analysis: where v0.2 falls short of that thesis

patient-zero today is **known-IoC matching**: it catches attacks *after* they're in the
database. The vibe-coder threat model is dominated by things that are **unknown at install
time**:

| Threat | Caught by v0.2? |
|---|---|
| Known campaign (Shai-Hulud, chalk phish…) | ✓ scan + install block |
| Hallucinated (slopsquatted) package name | ✗ — not in any IoC feed |
| Brand-new malicious version (< 48h old) | ✗ until aggregator picks up an advisory |
| Agent auto-running `npm install` outside our interceptor | ✗ — nothing wires us into the agent |
| Malicious repo/skill the agent clones (HalluSquatting) | ✗ — we only scan MCP configs |
| pip/uv installs | ✗ — interceptor is npm-only |

Everything below is about closing those rows.

## Roadmap

### P0 — `patient-zero protect`: wire into the agent itself (the killer feature)

One command that installs patient-zero as a **PreToolUse hook for Claude Code** (and the
equivalent for Cursor hooks, Gemini CLI, Codex CLI):

```sh
npx patient-zero protect          # detects installed agents, wires hooks, idempotent
```

- Hook intercepts Bash tool calls matching install commands
  (`npm i`, `npm ci`, `npx`, `pnpm add`, `yarn add`, `pip install`, `uv add`, `poetry add`),
  routes them through `patient-zero install`, and returns block/allow (exit 2 blocks in
  Claude Code; JSON `{decision: "block", reason}` gives the agent an explanation it can act on).
- The reason string teaches the agent: "chalk@4.0.0 matches IoC GHSA-demo-chalk; install a
  clean version instead" — the agent self-corrects without the user doing anything.
- We already have the hook-installer pattern (`src/hook-installer.js`) for git hooks;
  this reuses it for agent config files.
- **This is the marketing headline**: *"Your agent is in auto mode. patient-zero is the one
  prompt it can't skip."*

### P0 — Unknown-threat heuristics in the install interceptor

Known-IoC matching alone can't catch slopsquatting. Add cheap, offline-friendly checks to
`patient-zero install` (each a warning/block with its own severity, configurable):

1. **Existence + age gate ("cooldown")** — query the registry: package or version published
   < N days ago (default 7) → warn; < 48h → block by default. Cooldown users were protected
   from Shai-Hulud *before advisories existed* — it's the single highest-value heuristic in
   this space, and it requires zero curation.
2. **Slopsquat/typosquat distance** — edit-distance + token-similarity against a bundled
   top-10k popular-package list; flag "looks like `lodash` but isn't" and
   plausible-but-nonexistent scoped names (`@modelcontextprotocol/*` style — we already do
   this for MCP, generalize it).
3. **Risk signals** — has install scripts (`postinstall`), maintainer changed in last 30
   days, near-zero downloads, repository field missing or pointing at a different package
   name. Score, don't hard-block, to keep false positives from eroding trust.

### P1 — Python parity + universal wrapper

- Extend the install interceptor to **pip / uv / poetry** (scanners already parse Python
  lockfiles; interception is the missing half).
- `patient-zero shim` — shell aliases for `npm`/`npx`/`pnpm`/`yarn`/`pip`/`uv` (the Aikido
  safe-chain pattern) so installs are covered even in terminals with no agent hook.

### P1 — HalluSquatting coverage: repos and skills, not just packages

Agents don't only install packages; they clone repos and install skills/plugins. Extend
scanning + interception to:

- `git clone` targets: repo exists, has history/stars/age, name isn't a near-miss of a
  trending repo.
- Agent skill/plugin directories (`.claude/skills`, plugin marketplaces, Cursor rules):
  same IoC + heuristic treatment MCP configs get today. Nobody covers this lane either —
  it extends the moat we already claim for MCP configs.

### P2 — Distribution for vibe coders (they won't find a security CLI on their own)

- **Claude Code plugin + Cursor extension** listings — meet them in the marketplace they
  already browse; the plugin is just `protect` with a UI.
- **MCP server mode** (`patient-zero mcp`) so any agent can call the scanner as a tool and
  agents can be instructed "check installs with patient-zero" in a rules file.
- Ready-to-paste **rules snippets** (CLAUDE.md / .cursorrules) in the README.
- README badge ("protected by patient-zero"), and fast incident-day writeups — the
  `npx patient-zero` moment when an attack hits Hacker News is our whole acquisition funnel.
- Reposition the README top: lead with the agent story ("You vibe code. Your agent
  installs things you never see.") rather than the incident-triage story.

## Positioning line

> **patient-zero — vibe code without getting infected.**
> Your AI agent installs packages you never see. patient-zero is the hook it can't skip:
> blocks known supply-chain malware, hallucinated packages, and day-zero uploads before
> `postinstall` ever runs. Free, offline-capable, no signup.

## Sources

- [The Hacker News — HalluSquatting attack](https://thehackernews.com/2026/07/new-hallusquatting-attack-could-trick.html)
- [SC Media — HalluSquatting enables scalable botnets](https://www.scworld.com/brief/hallusquatting-new-ai-attack-method-enables-scalable-botnets-and-large-scale-infections)
- [Endor Labs — Slopsquatting: when AI agents hallucinate malicious packages](https://www.endorlabs.com/learn/slopsquatting-when-ai-agents-hallucinate-malicious-packages)
- [VentureBeat — slopsquatting as the AI-era supply-chain threat](https://venturebeat.com/security/forget-typosquatting-slopsquatting-is-the-software-supply-chain-threat-created-by-ai-coding-tools)
- [Help Net Security — USENIX package-hallucination study (19.7% / 205k names)](https://www.helpnetsecurity.com/2025/04/14/package-hallucination-slopsquatting-malicious-code/)
- [Snyk — package hallucinations and mitigation](https://snyk.io/articles/package-hallucinations/)
- [StepSecurity — securing vibe coding end-to-end (cooldown policies)](https://www.stepsecurity.io/blog/securing-vibe-coding-and-ai-coding-agents-an-end-to-end-approach-with-stepsecurity)
- [Claude Code hooks reference (PreToolUse)](https://code.claude.com/docs/en/hooks)
- [DEV — Claude Code hooks as security gates](https://dev.to/jangwook_kim_e31e7291ad98/claude-code-hooks-security-gates-for-agent-workflows-5he7)
- [OpenReplay — running coding agents in YOLO mode safely](https://blog.openreplay.com/coding-agents-yolo-mode/)
- [Tech Times — AI coding agents skip package verification](https://www.techtimes.com/articles/319457/20260701/ai-coding-agents-skip-package-verification-attackers-are-exploiting-it.htm)
- [mintmcp/agent-security — hooks for Claude Code & Cursor (prior art)](https://github.com/mintmcp/agent-security)
