# Safe Circle AI

Personal-safety toolkit. No accounts, no servers, no tracking: your data stays on your own device.

| Where | What | Folder |
|---|---|---|
| Phones (iOS/Android) and any browser | Installable web app (PWA): ShadowWatch, Privacy Guardian, PatternLock, Safe Response, lessons, tracker sweep checklist. Works offline. | `docs/` |
| Windows / macOS / Linux | Desktop app with real Bluetooth tracker scanning, SQLite evidence log, email/Telegram alerts | `desktop/` |

## Publish the phone app (free, 5 minutes)
1. Create a GitHub repo and upload everything in this folder.
2. Repo Settings > Pages > Deploy from branch `main`, folder `/docs`.
3. Open the Pages link on your phone: Android Chrome "Install app", iPhone Safari Share > "Add to Home Screen".

## Publish the desktop apps
Push a tag (`git tag v1.0.0 && git push --tags`). GitHub Actions builds Windows, macOS and Linux files and attaches them to a Release that anyone can download.

## Known limits
- Unsigned apps show a security warning (Windows SmartScreen, macOS Gatekeeper). Code-signing certificates remove it.
- The macOS build needs to be packaged as a signed `.app` with a Bluetooth usage description before Bluetooth scanning will work there.
- Phones: browsers cannot scan Bluetooth trackers. Use the built-in iPhone/Android tracker alerts, or build a native Android app.
- Not a replacement for emergency services or professional support.
