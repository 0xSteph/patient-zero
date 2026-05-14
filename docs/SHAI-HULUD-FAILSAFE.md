# If patient-zero flagged a Shai-Hulud finding

**Read this entire page before taking any defensive action.**

The Shai-Hulud npm worm (and its successor Shai-Hulud 2.0) installs a persistence daemon called `gh-token-monitor` that watches for **token revocation** as a signal that the compromise has been detected. If the daemon observes revocation, it triggers a destructive failsafe.

Reported behavior of the failsafe: `rm -rf ~/` on the affected user account.

This means the **standard incident-response reflex of "rotate tokens immediately" is the most dangerous thing you can do** on a machine that has the daemon armed.

## The correct order

1. **Isolate the machine from the network.**
   - Wi-Fi off. Ethernet unplugged. Cellular hotspots disabled.
   - Do not skip this step. The daemon needs network access to detect revocation.

2. **Identify the persistence.**
   - macOS: `ls -la ~/Library/LaunchAgents/ | grep gh-token` and `ls -la /Library/LaunchDaemons/ | grep gh-token`
   - Linux: `systemctl --user list-units | grep gh-token` and `systemctl list-units | grep gh-token`
   - Note the exact plist or unit file path.

3. **From a SEPARATE, isolated terminal — disable the persistence.**
   - macOS: `launchctl unload <plist-path>` then `rm <plist-path>`
   - Linux: `systemctl --user stop <unit>` then `systemctl --user disable <unit>` then remove the unit file
   - Verify the process is no longer running: `ps aux | grep gh-token-monitor`

4. **Only after persistence is fully removed: rotate credentials.**
   - npm: revoke all access tokens, regenerate, update `.npmrc`
   - GitHub: revoke all PATs and OAuth apps you don't recognize, regenerate, update `gh` auth
   - Any other tokens that were in environment variables during the install window

5. **Audit recent activity.**
   - GitHub: `https://github.com/settings/security-log`
   - npm: `https://www.npmjs.com/settings/<username>/audit-log`
   - Look for: new repos you didn't create, new tokens you didn't issue, packages published from your account, packages with names matching Shai-Hulud patterns.

6. **Reconnect to the network only after steps 1–5 are complete.**

## What we don't know

- Whether every variant of Shai-Hulud has the same failsafe behavior.
- Whether the failsafe trigger has evolved beyond token revocation.
- Whether a partially-disabled persistence (process killed but plist still present) can re-arm on reboot.

Given these unknowns, treat **every** Shai-Hulud finding as if the failsafe is armed. The cost of caution is two extra steps; the cost of the wrong reflex is your home directory.

## If you've already revoked a token before reading this

- Stop. Don't take more actions.
- Power-cycle the machine (do not reboot — power off, wait 30 seconds, power on).
- Boot to recovery / a live USB if available.
- Back up critical files from the disk to external storage before booting the affected user account again.
- Treat the user account as compromised regardless.

## Primary sources

- [StepSecurity — Shai-Hulud: The npm Worm Explained](https://www.stepsecurity.io/blog/shai-hulud-the-npm-worm-explained)
- [Microsoft Security — Shai-Hulud 2.0 detection guidance](https://www.microsoft.com/en-us/security/blog/2025/12/09/shai-hulud-2-0-guidance-for-detecting-investigating-and-defending-against-the-supply-chain-attack/)

If you found a difference between what we've documented here and what you observed in the wild, please [report it](../SECURITY.md). Accurate failsafe guidance is the highest-leverage thing this project ships.
