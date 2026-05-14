# patient-zero README research

Launch playbook. Inputs: ten READMEs, web research on launch mechanics, Shai-Hulud detector landscape. Audience: the engineer drafting the README next.

---

## 1. Studied READMEs (one-paragraph takeaway each)

**Aikido Safe Chain** (`AikidoSec/safe-chain`). Leads with a branded banner, then four bullets that read like a sales sheet: "Block malware on developer laptops and CI/CD," "Tokenless, free, no build data shared." Two badges only (NPM version, NPM downloads). Demo is an animated **GIF** of malware being blocked at install time. Trust comes from positioning Safe Chain as the free tier of "Aikido Intel" threat intel — corporate parent provides credibility without owning the OSS. **Takeaway:** if you have an enterprise parent, the free tool is a funnel and the README admits it cleanly. We don't, so we have to earn trust differently.

**osv-scanner** (`google/osv-scanner`). Tagline: "Use OSV-Scanner to find existing vulnerabilities affecting your project's dependencies." Five credential badges (OpenSSF Scorecard, Go Report Card, codecov, SLSA 3, GitHub Release) — pure third-party validation stack. Trust is Google brand + SLSA 3 + "11+ language ecosystems, 19+ lockfile types" (numbers, not adjectives). **Takeaway:** credential-stacking with third-party security badges (OpenSSF Scorecard, SLSA) is the move when you can't lean on a brand. Quote scope numbers; don't say "comprehensive."

**trufflehog** (`trufflesecurity/trufflehog`). Opening line: "TruffleHog is the most powerful secrets **Discovery, Classification, Validation,** and **Analysis** tool." Pixel-pig logo, "~800+ detectors" as the headline trust signal. SVG animation demo (not GIF, not asciinema — an animated SVG). Six install paths immediately after demo. **Takeaway:** for a detection tool, the size of the detection catalog *is* the trust signal. Show the number above the fold.

**gitleaks** (`gitleaks/gitleaks`). Opens with ASCII art, then: "Gitleaks is a tool for **detecting** secrets like passwords, API keys, and tokens in git repos, files, and whatever else you wanna throw at it via `stdin`." Demo is a **fenced code block** showing a real finding (rule ID, entropy, fingerprint). Sponsor logo (CodeRabbit) visible. **Takeaway:** A static code-block demo of a realistic finding outperforms a GIF for security tools because readers can *parse* it. Informal voice ("whatever else you wanna throw at it") humanises the tool.

**dependency-cruiser** (`sverweij/dependency-cruiser`). Tagline is *italic*: "*Validate and visualise dependencies. With your rules.*" Self-validates: "dependency-cruiser uses itself to check on itself in its own build process." **Takeaway:** dogfooding statements are a free, durable trust signal. We can write "patient-zero runs against its own dependencies in CI" if we wire it up.

**htmx** (`bigskysoftware/htmx`). Tagline: "*high power tools for HTML*." Four badges (Discord, Netlify, dependencies, minzip size). Includes a footer haiku. Disambiguates itself from "the old broken `htmx` package" on npm. **Takeaway:** htmx hit virality on personality, not feature lists. The lesson for a security tool is narrower — pick one piece of distinctive voice (a slogan, a haiku, a CLI banner), and let everything else be sober.

**bun** (`oven-sh/bun`). Tagline: "Bun is an all-in-one toolkit for JavaScript and TypeScript apps." Positions as "a drop-in replacement for Node.js" — direct comparison in line one. CTA "[Read the docs →]" appears immediately after badges, before any explanation. **Takeaway:** the most aggressive CTA pattern works when you have a one-sentence value prop. We don't have a "drop-in replacement" line; we have "scans for known IoCs," so a docs link can't be our first CTA.

**Cobenian/shai-hulud-detect** (discovered). Tagline: "A Bash tool that helps you spot known traces of the September 2025 through May 2026 npm and PyPI supply-chain attacks." **No demo medium** — uses exit code contracts (0/1/2) and a 43-test suite as the trust mechanism. Honest about limits: "This script is for detection only. It does not...automatically remove malicious code." **Takeaway:** our closest sibling. They earn trust by naming exact campaigns by date, citing 6+ firms, and admitting what the tool can't do. Copy this pattern.

**gensecaihq/Shai-Hulud-2.0-Detector** (discovered). Tagline: "Protect your projects from the Shai-Hulud 2.0 npm supply chain attack." Crisis-communication framing — first prompt is "🚨 Found a Compromised Package? Report It!", not "Install me." Frames users as collaborators in a community database. **Takeaway:** in a fresh-attack window, the README can lead with "help us index" instead of "install us." Worth a section in our docs even if it's not the hero.

**omarpr/mini-shai-hulud-ioc-scanner** (discovered). Tagline: "**This is a triage helper, not a guarantee that a machine is clean.**" Badges include `Network: no_uploads` and `Deep Checks: opt-in` — they invented custom badges to encode trust properties. **Takeaway:** custom non-shields.io badges can encode things like `telemetry: none`, `network: none`, `signup: none` directly in the hero. This is our move for the "no telemetry, no signup" trust signals.

---

## 2. Structural elements common to high-star READMEs

1. **Logo or wordmark + sub-150-char tagline at the top.** Every studied README does this. The tagline does the heavy lifting; the logo is identity, not value. bun, htmx, dependency-cruiser, osv-scanner all follow this.
2. **Badge row immediately under the tagline.** Five to eight badges max. shields.io recommends "build status, version, license, and coverage" plus 1–3 distinctive ones (Bun's `fast` badge, osv-scanner's SLSA 3, mini-shai-hulud's `no_uploads`).
3. **One-paragraph problem statement before any install command.** osv-scanner and gitleaks both do this in 2–3 sentences. Don't skip straight to install — give the reader the "why."
4. **Demo before install.** Aikido (GIF), gitleaks (code block), trufflehog (SVG anim), osv-scanner (screencast). Demo medium varies; demo position does not.
5. **Multi-path install block.** trufflehog has six, gitleaks has three, Aikido has a curl one-liner + package manager paths. Reduces friction across reader environments.
6. **Quick-start usage example in the same fenced block style as install.** dependency-cruiser shows `npx depcruise --init` immediately under `npm install`. Reader should see "install → command → first output" in one screen.
7. **"What it does / what it doesn't do" honesty section.** Cobenian and omarpr both have explicit limitations. This is a security-tool genre convention and we'd look amateur skipping it.
8. **Independent-source attribution for security tools.** Cobenian links to six firms (StepSecurity, Socket, Semgrep, JFrog, Wiz, Snyk, Aikido). gensecaihq lists seven vendor sources. Trust laundered from established names.
9. **Exit-code contract documented.** Cobenian documents 0/1/2 explicitly. CI/CD users *need* this to adopt; it doubles as a deterministic-behavior trust signal.
10. **Footer with license, contributing link, and sometimes a sponsor or community link.** Gitleaks has CodeRabbit sponsor logo + Discord. dependency-cruiser links downstream contribs. Footer is where you put the social proof that doesn't fit above the fold.

---

## 3. Writing patterns that work

- **Short opener; specific, not adjective-heavy.** "A Bash tool that helps you spot known traces of the September 2025 through May 2026 npm and PyPI supply-chain attacks" (Cobenian) outperforms anything with the word "comprehensive."
- **Date-anchor the scope.** "September 2025 through May 2026" is more trustworthy than "all known attacks" because it's falsifiable.
- **State what the tool isn't.** "This is a triage helper, not a guarantee that a machine is clean" (omarpr) is the gold-standard line. Steal the shape.
- **Verbs of action in CLI examples, never marketing copy in code blocks.** `npx patient-zero scan` not `# Scan your project for threats`.
- **Sentence length under 25 words in the conversion zone (first 200 lines).** htmx, gitleaks, bun all hover around 12–18-word sentences in the hero.
- **The trust question ("is this legit?") is answered with three independent kinds of evidence, not three flavors of the same evidence.** Cobenian uses: (a) named campaigns with dates, (b) external security-firm citations, (c) a runnable test suite. Three vectors, not three adjectives.
- **No hedge words in the hero.** "Designed to," "aims to," "intended for" — all kill conversion. Pick the verb and commit. bun: "ships as a single executable." gitleaks: "detects secrets."

---

## 4. Visual elements — opinionated recommendation

**Demo tool: pick VHS (charmbracelet/vhs). Defend below.**

| Tool | Output | CI-rebuildable | Editable after recording | Best for |
|---|---|---|---|---|
| asciinema | `.cast` (JSON) | Manual record | Hard (re-record) | Live web playback |
| **VHS** | **GIF, MP4, WebM** | **`.tape` script, runs in CI** | **Edit the `.tape` file** | **Docs/README** |
| terminalizer | YAML config → GIF | Yes | Yes | Similar to VHS, smaller community |
| freeze.dev | Static PNG/SVG of one frame | Yes | Trivial | Single-finding screenshot |
| Static screenshot | PNG | n/a | n/a | One-shot output |

**Why VHS:** A `.tape` file lives in the repo. CI re-renders the GIF on every release, so the README demo never goes stale when the CLI output format changes. It's also the de-facto 2025–2026 standard for trending CLI READMEs (HN discussion volume confirms). Asciinema is great for tutorials but requires JS embed or a `<a>` link out — GitHub README renders the cast as a link, not inline. VHS gives you an inline GIF that works on GitHub, npm, and any mirror.

**Fallback for "single finding" hero shot:** freeze.dev — produces a syntax-highlighted PNG of a fenced terminal block. Use this for the *result* of a scan; use VHS for the *flow* of a scan.

**Hero image: no logo above the demo.** Logos slow the demo. Put the wordmark inline with the title, badges underneath, demo immediately under badges. Save the bigger brand image (if any) for a `docs/assets/` directory linked from CONTRIBUTING.

**Badges (shields.io conventions):**

- **Hero row (5–7 max):** npm version · npm weekly downloads · CI status · license (MIT) · Node version requirement · `telemetry: none` (custom) · `signup: none` (custom).
- **Skip:** code coverage (irrelevant to users), repo size, last-commit (it ages badly), discord (only if active).
- **Style:** flat-square, consistent across the row. Bun and Aikido both do this.
- **Custom badges:** omarpr-style invented badges (`no_uploads`, `triage_helper`) work because they encode trust properties that no stock badge covers. We should mint `no-telemetry`, `no-signup`, `runs-offline` badges.

---

## 5. Trend mechanisms — how the studied projects caught fire

- **osv-scanner**: Google blog launch + OpenSSF inclusion. Institutional megaphone. Not replicable for us.
- **trufflehog**: DEF CON talks (Truffle Security has presented for years) + the *number of detectors* doing the marketing on Twitter ("trufflehog now detects 800+ secret types" travels well).
- **gitleaks**: GitHub Actions Marketplace + pre-commit hooks distribution. Got into other people's CI by being trivial to wire in. The Marketplace listing itself is a trend channel.
- **dependency-cruiser**: Long-tail awesome-list and Stack Overflow accumulation. Not a viral spike — slow compound.
- **Aikido Safe Chain**: Aikido's existing brand + co-promotion across npm supply-chain attack news cycles. Each attack = a fresh Aikido blog post = a fresh Safe Chain plug.
- **htmx**: Twitter personality (the @htmx_org account is genuinely funny) + "$$\text{HATEOAS}$$" T-shirts + conference circuit. Pure cult-of-personality play.
- **bun**: Founder-led launch (Jarred Sumner) + benchmarks on launch day + Vercel/Twitter endorsements. The benchmark *was* the launch.
- **Cobenian/shai-hulud-detect**: News-cycle riding. Published immediately after Shai-Hulud broke, got linked from incident-response writeups.
- **gensecaihq/Shai-Hulud-2.0-Detector**: GitHub Marketplace listing + community-database framing (people PR'ing new IoCs).
- **omarpr/mini-shai-hulud-ioc-scanner**: TanStack attack news-cycle ride (May 2026).

**The pattern that actually applies to us:** news-cycle riding. Every studied recent-launch security tool surfed an attack wave within 72 hours of breaking news. Cobenian and the gensecaihq detector both timed their public launches to within days of the Shai-Hulud 2.0 disclosure (late Nov 2025). The next attack will come — pre-build the README and have a `<!-- INSERT INCIDENT BLOCK -->` placeholder so we can ship within hours.

**HN title formulas that work for security tools** (from the IndieHackers + markepear.dev guides):

- `Show HN: patient-zero – npx CLI that scans for npm supply-chain IoCs`. Specific, no adjectives, "Show HN:" prefix, hyphen-dash separator.
- *Skip:* "the easiest way to," "powerful," "comprehensive," exclamation points, year in the title.
- Best time window: **Tue–Thu, 14:00–17:00 UTC** per HN posting guides.
- Include "open source" or the install verb (`npx`) in the title — HN over-indexes on both.

**Awesome-list PR targets** (real, found via search):

- `lirantal/awesome-nodejs-security`
- `lirantal/npm-security-best-practices`
- `bodadotsh/npm-security-best-practices`
- `sbilly/awesome-security`

Submit a PR for each within 48 hours of launch.

---

## 6. Ten opinionated, concrete principles for our README

1. **Lead with a 12-second VHS terminal demo above any prose; place it before the install command; do not show a logo above the demo because logos delay the demo.** The demo IS the value prop for a CLI.
2. **The first line under the H1 is a one-sentence scope statement with a date range, not a tagline.** Example: "Scans Node, Python, and AI-agent configs for indicators of compromise from npm and PyPI supply-chain attacks (Sept 2025 – present)." Date range makes it falsifiable, which is the highest-grade trust signal for a security tool.
3. **Mint three custom shields.io badges in the hero row: `telemetry: none`, `signup: none`, `runs: offline`.** No stock badge encodes these; minting them puts the four trust signals (free/MIT/no-telemetry/no-signup) literally in the hero. Stolen from omarpr.
4. **Show the install as one line, copy-pasteable, and `npx`-prefixed.** `npx patient-zero@latest`. No `npm i -g`, no clone-repo step. The "zero install" promise is dead the moment we ask for a global install.
5. **Document the exit-code contract (0/1/2) in a fenced block in the README, not in `--help` only.** CI/CD readers scan for this before they install. Cobenian does this; we copy it.
6. **Every named attack we detect gets a row in a table: name, date, ecosystem, IoC type, primary external source link.** Reader can verify scope claims against StepSecurity/Wiz/Snyk in one click. This is what Cobenian did and it's the single biggest credibility move available to a small-team security tool.
7. **A "What this is NOT" section appears before "Features."** Sample line: "patient-zero is not an EDR, not a Snyk/Aikido replacement, not a runtime sandbox. It's a first-aid kit you run when news breaks." Frames the tool *into* its niche rather than out of competitors'.
8. **The destructive-failsafe warning (Shai-Hulud `gh-token-monitor` daemon → `rm -rf ~/`) lives in a `docs/SHAI-HULUD-FAILSAFE.md` linked from the README, NOT in the hero.** Use Cobenian's pattern: a one-line "If patient-zero flags `shai-hulud-failsafe-daemon`, **read this before rotating any token** →" in the findings-output guide section. Operational guidance before the scary fact. Casual landing-page visitors never see the warning unless their scan triggers it.
9. **Pin a single-source-of-truth IoC list under `data/iocs.json` and link it from the README hero.** "Detects these IoCs ↗" as a visible link near the badges. This is dependency-cruiser's "we dogfood our own thing" trust move applied to detection scope — readers can audit our coverage list without running the tool.
10. **Footer carries: license, security contact (`SECURITY.md`), how to add an IoC (one-line PR template), and a single Twitter/Mastodon link for incident announcements.** No Discord. Discord communities go stale; an incident-feed account aligns with the news-cycle-riding distribution strategy.

---

## 7. Section-by-section outline for the README

| # | Section | Content (one line) | Rationale (conversion lost if cut) |
|---|---|---|---|
| 1 | H1 + scope sentence | `# patient-zero` + "Scans Node, Python, and AI-agent configs for IoCs from npm/PyPI supply-chain attacks (Sept 2025 – present)." | Reader bounces in 4 sec without a scope claim with a date. |
| 2 | Hero badge row | npm version · downloads · CI · MIT · Node ≥18 · `telemetry: none` · `signup: none` · `runs: offline` | The four trust signals (free/MIT/no-telemetry/no-signup) belong above the fold. |
| 3 | VHS demo GIF | 12–15 sec scan of an intentionally-infected fixture project. | Without this, the reader has no signal that the tool actually works. |
| 4 | One-line install | `npx patient-zero@latest` (then 2-line "or pin a version" alt). | "Zero install" only delivers if it's literally one line. |
| 5 | What it scans | Bulleted list: lockfiles · `node_modules` · processes · `~/.npmrc` · MCP server configs · Claude Desktop / Claude Code / Cursor configs · GitHub account. | Reader can't trust scope claims without enumeration. |
| 6 | What this is NOT | "Not an EDR. Not a Snyk replacement. Not a runtime sandbox. A first-aid kit for when news breaks." | Without this, savvy readers assume we're overpromising and bounce. |
| 7 | Covered attacks table | Name · date · ecosystem · IoC class · external source. Five to ten rows. | Falsifiable scope = credibility. Cobenian's biggest single trust move. |
| 8 | Exit codes | 0 clean · 1 IoC matched · 2 scanner error. Fenced block. | CI/CD adoption blocked until this is documented. |
| 9 | If patient-zero flags something | Numbered triage steps; links to `docs/RESPONSE.md` and the Shai-Hulud failsafe page. | This is where the destructive-failsafe warning surfaces *contextually* — only readers who already have a finding see it. |
| 10 | How it works (60 words) | Static IoC list + lockfile parse + process/config inspection. No phone-home. | Security audience won't trust a black box. |
| 11 | CI usage | GitHub Actions snippet + exit-code recipe. | Distribution channel — gitleaks-style "get into other people's CI." |
| 12 | Contributing a new IoC | One-line PR template + link to `data/iocs.json`. | Recruits the community-database flywheel gensecaihq used. |
| 13 | Comparison to Snyk / Socket / Aikido / osv-scanner | One-paragraph honest matrix: "those are continuous platforms; this is a 30-second scan you run when news breaks." | Without explicit positioning, reviewers will write the comparison *for* us, usually badly. |
| 14 | Security disclosure | Link to `SECURITY.md`. | Genre convention; absence reads as amateur. |
| 15 | License + footer | MIT + maintainer + incident-feed social link. | Closes the trust loop. |

---

## Sources

- [Aikido Safe Chain](https://github.com/AikidoSec/safe-chain)
- [osv-scanner](https://github.com/google/osv-scanner)
- [trufflehog](https://github.com/trufflesecurity/trufflehog)
- [gitleaks](https://github.com/gitleaks/gitleaks)
- [dependency-cruiser](https://github.com/sverweij/dependency-cruiser)
- [htmx](https://github.com/bigskysoftware/htmx)
- [bun](https://github.com/oven-sh/bun)
- [Cobenian/shai-hulud-detect](https://github.com/Cobenian/shai-hulud-detect)
- [gensecaihq/Shai-Hulud-2.0-Detector](https://github.com/gensecaihq/Shai-Hulud-2.0-Detector)
- [omarpr/mini-shai-hulud-ioc-scanner](https://github.com/omarpr/mini-shai-hulud-ioc-scanner)
- [Amruth-SV/shai-hulud-scanner](https://github.com/Amruth-SV/shai-hulud-scanner)
- [VHS by Charm Bracelet](https://github.com/charmbracelet/vhs)
- [shields.io](https://shields.io/)
- [IndieHackers: How to hack Hacker News](https://www.indiehackers.com/post/how-to-hack-hacker-news-and-consistently-hit-the-front-page-56b4a04e12)
- [markepear: How to launch a dev tool on Hacker News](https://www.markepear.dev/blog/dev-tool-hacker-news-launch)
- [awesome-nodejs-security](https://github.com/lirantal/awesome-nodejs-security)
- [Microsoft: Shai-Hulud 2.0 detection guidance](https://www.microsoft.com/en-us/security/blog/2025/12/09/shai-hulud-2-0-guidance-for-detecting-investigating-and-defending-against-the-supply-chain-attack/)
- [StepSecurity: Mini Shai-Hulud + TanStack](https://www.stepsecurity.io/blog/mini-shai-hulud-is-back-a-self-spreading-supply-chain-attack-hits-the-npm-ecosystem)
