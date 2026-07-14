# URLGuard — Phishing URL Detector

A web app that scores any URL for phishing risk in real time, combining a
custom rule-based detection engine with a live lookup against Google's
Safe Browsing threat database.

Built as a way to apply web security fundamentals and API integration to
a real, working tool rather than a theoretical exercise.

## What it does

Paste a URL and URLGuard runs it through nine heuristic checks — the same
category of signals used in real anti-phishing research — then
cross-references it against Google Safe Browsing's continuously updated
list of confirmed malicious URLs. You get a risk score (0–100), a verdict
(safe / suspicious / dangerous), and the specific reasons behind the score.

**Rule-based checks include:**
- Raw IP address instead of a domain name
- Punycode / homograph domain tricks
- Brand impersonation (e.g. `paypal-secure-login.xyz`)
- Suspicious keywords (`verify`, `suspend`, `login`, etc.)
- Excessive subdomains
- `@` symbol used to hide the real destination
- Link shorteners masking the true URL
- Abnormally long URLs
- Typosquatting patterns (repeated hyphens)

The app works fully offline with just the rule engine. Add a free Google
Safe Browsing API key to also cross-check against real-world confirmed
threats.

## Tech stack

- **Backend:** Python, Flask
- **Frontend:** vanilla HTML/CSS/JS (no framework — kept intentionally lightweight)
- **Threat intel:** Google Safe Browsing API v4
- **Detection logic:** custom rule engine (`detector.py`)

## Running it locally

```bash
git clone https://github.com/YOUR_USERNAME/phishing-detector.git
cd phishing-detector
pip install -r requirements.txt
python app.py
```

Then open `http://127.0.0.1:5000` in your browser.

### Enabling live threat-intel lookups (optional)

1. Get a free API key: https://developers.google.com/safe-browsing/v4/get-started
2. Copy `.env.example` to `.env` and add your key
3. Export it before running: `export SAFE_BROWSING_API_KEY=your_key_here`

Without a key, the app still works — it just relies on the rule engine
alone and tells you the live check was skipped.

## Project structure

```
phishing-detector/
├── app.py              # Flask routes
├── detector.py         # Rule-based detection engine (pure functions, unit-testable)
├── threat_intel.py      # Google Safe Browsing API integration
├── templates/
│   └── index.html
├── static/
│   ├── css/style.css
│   └── js/script.js
└── requirements.txt
```

## Why rule-based + API, not just one

Rule-based checks catch structural red flags instantly and work with zero
external dependency — useful when a URL is brand new and hasn't been
reported anywhere yet. The Safe Browsing API catches known threats that
don't necessarily look suspicious on the surface. Combining both gives
better coverage than either alone.

## Possible extensions

- WHOIS domain-age lookup (very new domains are higher risk)
- Browser extension wrapper
- Batch-scan mode for a list of URLs via CSV upload

## Author

Rudra Rathod — [LinkedIn](https://linkedin.com/in/rudra-rathod-ba3472268)
