# Safe Circle AI (Python)

A local personal-safety app. Flask + SQLite + real Bluetooth scanning.

## Run
    pip install -r requirements.txt
    python safecircle.py
Open http://127.0.0.1:5000 (only reachable from your own computer).

## What is real
- **TrackShield**: scans Bluetooth every minute with `bleak` and recognises Apple Find My (AirTag-type), Tile, Samsung SmartTag and Chipolo advertisements. A tracker seen in 4+ scans over 15+ minutes is "Watch"; 6+ scans over 30+ minutes is "Likely following you". Carry the computer (or a Raspberry Pi) with you while it scans.
- **Privacy Guardian**, **ShadowWatch**, **PatternLock**: real logic, stored in `safecircle.db`. Evidence exports to CSV.
- **Safe Response**: sends real alerts by email and/or Telegram when configured:

      export SC_SMTP_HOST=smtp.gmail.com SC_SMTP_USER=you@gmail.com SC_SMTP_PASS=app-password
      export SC_TG_TOKEN=<bot token from @BotFather>      # contact needs their Telegram chat ID
      export SC_AUTO_NOTIFY=1                              # optional: auto-alert on high-risk tracker

## Limits
- Detection is heuristic. Tracker addresses rotate and some trackers (e.g. Google network tags) are not covered. A flag means "check", not proof. Also use your phone's built-in tracker alerts.
- On Linux you may need Bluetooth permission; on macOS allow Bluetooth for your terminal.
- A laptop can't track your location, so "following" is judged by how long a tracker stays near you.
- If you are in danger, call your local emergency number first (112 in India).
