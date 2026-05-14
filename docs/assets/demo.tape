# VHS recording script for the patient-zero README demo.
#
# Render with:    vhs docs/assets/demo.tape
# Output:         docs/assets/demo.gif
#
# Demo: scan a project that pulled chalk@4.0.0 (the Sept 2025 maintainer-phish
# version). Uses a local fixture IoC database so the demo is self-contained
# and reproducible from a clean checkout — no real machine state required.
#
# Implementation note: we use a shell *function* (not an alias) so the
# absolute path to bin/cli.js gets resolved once at definition time. An
# alias would re-evaluate $PWD at invocation time and break after `cd`.

Output docs/assets/demo.gif

Set FontSize 14
Set Width 1100
Set Height 620
Set Theme "Catppuccin Mocha"
Set TypingSpeed 50ms
Set PlaybackSpeed 1.0

# ── Setup (hidden) — bake absolute paths, define `patient-zero` as a function,
#    cd into the demo project, clear the prompt for a clean recording.
Hide
Type "PZ_BIN=$PWD/bin/cli.js"
Enter
Type "PZ_IOCS=$PWD/docs/assets/demo-iocs.json"
Enter
Type 'patient-zero() { PATIENT_ZERO_IOCS_PATH="$PZ_IOCS" node "$PZ_BIN" --no-github "$@"; }'
Enter
Type "cd docs/assets/demo-project"
Enter
Type "clear"
Enter
Sleep 200ms
Show

# ── Visible — the demo a viewer actually sees.
Type "# Did chalk's Sept-2025 compromise touch this project?"
Enter
Sleep 800ms

Type "patient-zero"
Sleep 500ms
Enter
Sleep 4s

# Trailing blank line + pause so the final frame is the report card, not the prompt.
Type ""
Sleep 2s
