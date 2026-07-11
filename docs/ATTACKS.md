# Tracked attacks

Auto-generated from [`data/iocs.json`](../data/iocs.json) by the [aggregator](../aggregator/). To add an attack family, see [docs/CONTRIBUTING.md](CONTRIBUTING.md). Every row must cite a `primary_external_source`.

**Coverage window:** 2025-09-08 → present  · **Families tracked:** 7  · **Indicators:** 6  · **Last updated:** 2026-07-11T00:01:41.842Z

| Attack family | First observed | Ecosystem | IoC class | Active threat | Source |
|---|---|---|---|---|---|
| Mini Shai-Hulud (TanStack May 2026) | 2026-05-01 | npm | package | yes | [StepSecurity](https://www.stepsecurity.io/blog/mini-shai-hulud-is-back-a-self-spreading-supply-chain-attack-hits-the-npm-ecosystem) |
| axios postinstall (March 2026) | 2026-03-12 | npm | package + network | no | [GitHub Advisory](https://github.com/advisories) |
| Shai-Hulud 2.0 | 2025-12-09 | npm | package + file + process + github | yes | [Microsoft Security](https://www.microsoft.com/en-us/security/blog/2025/12/09/shai-hulud-2-0-guidance-for-detecting-investigating-and-defending-against-the-supply-chain-attack/) |
| MCP server heuristics | 2025-12-01 | npm, pypi | mcp | yes | [patient-zero MCP IoC contributor guide](https://github.com/0xSteph/patient-zero/blob/main/docs/MCP-IOC-GUIDE.md) |
| SANDWORM_MODE | 2025-11-01 | npm | package + network | no | [Socket Research](https://socket.dev/blog) |
| Shai-Hulud | 2025-09-15 | npm | package + file + process + github | yes | [StepSecurity](https://www.stepsecurity.io/blog/shai-hulud-the-npm-worm-explained) |
| chalk maintainer phish | 2025-09-08 | npm | package | no | [Snyk Advisory](https://security.snyk.io/) |

---

> If `Active threat: yes` shows for a family, IoCs in that family represent campaigns still seen in the wild. `Active threat: no` families are tracked for forensic completeness; finding one of those on your machine still means you were affected and credentials may be exposed.
