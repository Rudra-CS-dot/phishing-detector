"""
Rule-based phishing URL detector.

Scores a URL against a set of well-known phishing heuristics used in
real-world anti-phishing research (IP-literal hosts, punycode/homograph
tricks, excessive subdomains, suspicious keywords, etc.) and returns a
risk score plus the specific reasons that triggered it.
"""

import re
from urllib.parse import urlparse

SUSPICIOUS_KEYWORDS = [
    "login", "verify", "account", "update", "secure", "banking",
    "confirm", "signin", "webscr", "password", "suspend", "unlock",
    "billing", "invoice", "security-alert",
]

# Domains frequently impersonated in phishing campaigns.
COMMONLY_SPOOFED_BRANDS = [
    "paypal", "amazon", "apple", "microsoft", "google", "netflix",
    "facebook", "instagram", "whatsapp", "bank", "chase", "hdfc",
    "icici", "sbi", "irs", "linkedin",
]

URL_SHORTENERS = [
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd",
    "buff.ly", "rebrand.ly", "cutt.ly",
]


def _is_ip_address(host: str) -> bool:
    return bool(re.match(r"^(\d{1,3}\.){3}\d{1,3}$", host))


def _has_punycode(host: str) -> bool:
    return "xn--" in host


def _count_subdomains(host: str) -> int:
    parts = host.split(".")
    # naive: anything beyond "domain.tld" counts as a subdomain level
    return max(0, len(parts) - 2)


def _looks_like_brand_spoof(host: str) -> str | None:
    """Flag hosts that mention a known brand but aren't that brand's real domain."""
    for brand in COMMONLY_SPOOFED_BRANDS:
        if brand in host and not host.endswith(f"{brand}.com"):
            return brand
    return None


def _has_suspicious_keyword(url: str) -> str | None:
    lowered = url.lower()
    for kw in SUSPICIOUS_KEYWORDS:
        if kw in lowered:
            return kw
    return None


def analyze_url(raw_url: str) -> dict:
    """
    Analyze a URL and return a dict:
        {
            "url": str,
            "risk_score": int (0-100),
            "verdict": "safe" | "suspicious" | "dangerous",
            "reasons": [str, ...]
        }
    """
    url = raw_url.strip()
    if not re.match(r"^https?://", url, re.IGNORECASE):
        url = "http://" + url

    parsed = urlparse(url)
    host = parsed.netloc.lower().split("@")[-1].split(":")[0]  # strip creds/port
    reasons = []
    score = 0

    if _is_ip_address(host):
        score += 30
        reasons.append("URL uses a raw IP address instead of a domain name")

    if _has_punycode(host):
        score += 25
        reasons.append("Domain uses punycode encoding (possible homograph attack)")

    subdomain_count = _count_subdomains(host)
    if subdomain_count >= 3:
        score += 20
        reasons.append(f"Unusually high number of subdomains ({subdomain_count})")
    elif subdomain_count == 2:
        score += 8
        reasons.append("Multiple subdomains present")

    spoofed = _looks_like_brand_spoof(host)
    if spoofed:
        score += 30
        reasons.append(f"Domain references brand '{spoofed}' but does not match its official domain")

    keyword = _has_suspicious_keyword(url)
    if keyword:
        score += 15
        reasons.append(f"URL contains sensitive keyword '{keyword}' often used in phishing links")

    if host in URL_SHORTENERS:
        score += 15
        reasons.append("URL uses a link shortener, which can mask the true destination")

    if "@" in parsed.netloc:
        score += 25
        reasons.append("URL contains '@' in the authority component (can hide the real destination)")

    if len(url) > 100:
        score += 10
        reasons.append("URL is unusually long")

    if re.search(r"-{2,}", host):
        score += 10
        reasons.append("Domain contains repeated hyphens, common in typosquatting")

    score = min(score, 100)

    if score >= 60:
        verdict = "dangerous"
    elif score >= 25:
        verdict = "suspicious"
    else:
        verdict = "safe"

    if not reasons:
        reasons.append("No known phishing indicators detected")

    return {
        "url": url,
        "host": host,
        "risk_score": score,
        "verdict": verdict,
        "reasons": reasons,
    }


if __name__ == "__main__":
    test_urls = [
        "https://www.google.com",
        "http://192.168.1.1/login",
        "http://paypal-secure-verify.suspicious-site.com/account/update",
        "https://bit.ly/3xyzabc",
        "http://xn--80ak6aa92e.com",
    ]
    for u in test_urls:
        result = analyze_url(u)
        print(f"{u}\n  -> {result['verdict'].upper()} (score={result['risk_score']})")
        for r in result["reasons"]:
            print(f"     - {r}")
        print()
