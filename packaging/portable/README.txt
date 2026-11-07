Mooring @VERSION@ - portable build
==================================

This folder is a complete, no-install copy of Mooring. Nothing is written to the
registry, to /Applications or to your user profile: everything stays in this folder.

The file named "portable" next to the app is the switch. Keep it there. Without it
Mooring starts as a normally installed app and uses the OS application-data folder.

Your data (vault, connections, audit log, known hosts) lives in "Mooring Data/",
created next to the app on first start. Back it up: a lost USB stick is a lost vault.
Mooring never falls back to another location; if this folder is read-only it tells
you and exits.

Before the first start
----------------------
1. Verify the download: compare the zip's SHA-256 with the SHA256SUMS file of the
   release (https://github.com/yyasar21/Mooring/releases) - see docs/release.md.
2. macOS: the first launch is blocked by Gatekeeper. Open System Settings > Privacy &
   Security, find "Mooring was blocked", click "Open Anyway" once.
   Windows: SmartScreen shows "Windows protected your PC". Click "More info", then
   "Run anyway" once. The build is not code-signed yet.
3. Windows needs the Microsoft Edge WebView2 Runtime (Evergreen). Windows 11 and
   most Windows 10 machines already have it. If Mooring reports it missing, run the
   Evergreen Bootstrapper from https://developer.microsoft.com/microsoft-edge/webview2/
   without administrator rights: it installs per user.

Updating
--------
Download the new portable zip, verify it, then replace everything in this folder
EXCEPT "Mooring Data" (and keep "portable"). The in-app updater is off in portable
mode on purpose; "Check for updates" only tells you that a new version exists.

Notes
-----
- On a network share, run one instance at a time.
- macOS: the UI's own window state (no secrets) stays under ~/Library/WebKit.
- Do not run xattr or other tricks on the app; the Gatekeeper step above is enough.
