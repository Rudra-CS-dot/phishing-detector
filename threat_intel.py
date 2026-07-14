"""
Optional real-time threat intelligence lookup via Google Safe Browsing API.

Works with a free API key from Google Cloud Console (Safe Browsing API,
no billing required for this quota). If no key is configured, the app
falls back gracefully to rule-based-only results.

Get a free key: https://developers.google.com/safe-browsing/v4/get-started
"""

import os
import requests

SAFE_BROWSING_URL = "https://safebrowsing.googleapis.com/v4/threatMatches:find"
API_KEY = os.environ.get("SAFE_BROWSING_API_KEY", "").strip()


def check_threat_intel(url: str) -> dict:
    """
    Query Google Safe Browsing for known-malicious URL matches.

    Returns:
        {"available": bool, "flagged": bool, "threat_types": [str], "error": str|None}
    """
    if not API_KEY:
        return {
            "available": False,
            "flagged": False,
            "threat_types": [],
            "error": "No API key configured (set SAFE_BROWSING_API_KEY to enable live lookups)",
        }

    payload = {
        "client": {"clientId": "phishing-detector-demo", "clientVersion": "1.0.0"},
        "threatInfo": {
            "threatTypes": [
                "MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"
            ],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}],
        },
    }

    try:
        resp = requests.post(
            SAFE_BROWSING_URL,
            params={"key": API_KEY},
            json=payload,
            timeout=5,
        )
        resp.raise_for_status()
        data = resp.json()
        matches = data.get("matches", [])
        return {
            "available": True,
            "flagged": len(matches) > 0,
            "threat_types": [m.get("threatType") for m in matches],
            "error": None,
        }
    except requests.RequestException as exc:
        return {
            "available": False,
            "flagged": False,
            "threat_types": [],
            "error": f"Threat intel lookup failed: {exc}",
        }
