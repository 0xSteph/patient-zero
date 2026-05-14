# VHS recording script for the patient-zero README demo.
#
# Render with:    vhs docs/assets/demo.tape
# Output:         docs/assets/demo.gif
#
# Demo content: simulates running `npx patient-zero` against a project that
# unknowingly pulled chalk@4.0.0 (the September 2025 maintainer-phish version).
# We use a local alias and fixture IoC database so this recording is fully
# self-contained and reproducible from a clean checkout.

Output docs/assets/demo.gif

Set FontSize 14
Set Width 1100
Set Height 620
Set Theme "Catppuccin Mocha"
Set TypingSpeed 50ms
Set PlaybackSpeed 1.0

# Setup (hidden) — alias the binary, set up the demo IoC fixture, cd into demo project.
Hide
Type "export PATIENT_ZERO_IOCS_PATH=$PWD/docs/assets/demo-iocs.json"
Enter
Type "alias patient-zero='node $PWD/bin/cli.js --no-github'"
Enter
Type "cd docs/assets/demo-project"
Enter
Type "clear"
Enter
Sleep 200ms
Show

# Visible — the user reads this and gets the point.
Type "# Did chalk's Sept-2025 compromise touch this project?"
Enter
Sleep 800ms

Type "patient-zero"
Sleep 500ms
Enter
Sleep 4s

Type ""
Sleep 2s
