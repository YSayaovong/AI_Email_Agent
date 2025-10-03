
Gmail Cleaner Agent — Automated Inbox Hygiene for Gmail

✨ Key Features:
• Scans Inbox, Spam, and Trash (backlog + new mail via time-based trigger)
• Dry‑run mode (labels only) for safe testing
• Whitelists trusted senders/domains (e.g., banks, school)
• Flags suspicious emails (adds “Suspicious – Review” + star)
• Labels important emails (adds “Important – Read” + mark important)
• Never opens links; uses conservative heuristics (SPF/DKIM, URLs, tone)
• Creates labels automatically on first run

🛠 Skills Used:
Google Apps Script (GmailApp), JavaScript, Regex, Email Header Analysis (SPF/DKIM), Automation & Scheduling

📦 How to Use (Apps Script):
1) Go to https://script.google.com → New project → name it “Gmail Cleaner Agent”
2) Replace default file with `Code.gs` from this repo
3) (Optional) File → Project settings → Upload `appsscript.json` (sets scopes/timezone)
4) Save, then Run `setup()` once → approve permissions
5) Add a time‑based trigger to run `processMailbox` (e.g., every 15 minutes)
6) Keep `DRY_RUN = true` for a few days; review labels in Gmail
7) When satisfied, set `DRY_RUN = false` (spam goes to Trash; still recoverable ~30 days)

✅ Mark Senders as Safe (Whitelist):
Edit `KEY_SENDERS` in `Code.gs` and add either a full email or a domain, e.g.:
- "teacher@schooldistrict.org"
- "schooldistrict.org"
Save and Run `processMailbox()` to apply to new mail. For already‑flagged threads, remove “Suspicious – Review” (and “Processed – GmailCleaner” if you want the agent to re‑evaluate them).

🔐 Defaults:
- No permanent deletion (`HARD_DELETE = false`)
- Conservative rules; SPF/DKIM failure alone does not mark as suspicious
- Never clicks links or fetches remote content

