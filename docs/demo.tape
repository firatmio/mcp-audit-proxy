# Records docs/demo.gif from scripts/demo.sh, with https://github.com/charmbracelet/vhs:
#
#   vhs docs/demo.tape
#
# Run it from the repository root with go on PATH.
#
# This version is for Windows. vhs starts its shell by name, and Windows finds
# "bash" in System32 (WSL) before Git Bash, so the tape starts PowerShell and
# hands over to Git Bash by its full path. On Linux or macOS, use
# `Set Shell "bash"` and delete the first Type/Enter/Sleep below.

Output docs/demo.gif

Require go

Set Shell "powershell"
Set FontSize 15
Set Width 1280
Set Height 640
Set Padding 18
Set TypingSpeed 0

# Off camera: switch to bash, build once so the demo's own build is quick, and
# keep the demo's temp directory inside the repository, so that the paths it
# prints say nothing about the machine (the Windows default shows the user
# name).
# pwd -P because under vhs $PWD can arrive as C:/..., and the colon in it would
# split PATH when the demo puts its bin directory there.
Hide
Type `& "$env:ProgramFiles\Git\bin\bash.exe" --noprofile --norc`
Enter
Sleep 3s
Type `PS1='$ '; export PATH=/usr/bin:$PATH; go build ./cmd/mcp-audit ./cmd/dummy-mcp-server && mkdir -p .demo-tmp && export TMPDIR="$(pwd -P)/.demo-tmp" TYPING_SPEED=0 PAUSE=1.1 && clear`
Enter
Sleep 15s
Type "./scripts/demo.sh"
Enter
Sleep 1500ms
Show

Wait+Screen@120s /github\.com\/firatmio/
Sleep 3s

Hide
Type "rmdir .demo-tmp; clear"
Enter
