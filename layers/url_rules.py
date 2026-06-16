"""
Layer 1 — URL Rule Engine
Pure logic, zero network calls. Runs in < 1ms.
"""
import math
import re
from collections import Counter
from urllib.parse import urlparse

import tldextract

# TLD suspiciousness scores (0-100)
SUSPICIOUS_TLDS = {
    "cyou": 70, "xyz": 35, "tk": 65, "ml": 55, "cf": 60,
    "gq": 60, "ga": 55, "top": 40, "click": 45, "link": 35,
    "online": 30, "site": 30, "pw": 55, "ws": 35, "cc": 25,
    "su": 45, "icu": 50, "buzz": 35, "vip": 30, "loan": 60,
    "win": 50, "download": 55, "accountant": 55, "date": 50,
    "racing": 50, "party": 45, "review": 40, "faith": 45,
}

BRAND_KEYWORDS = [
    "paypal", "apple", "microsoft", "google", "amazon", "netflix",
    "facebook", "instagram", "twitter", "linkedin", "chase", "bankofamerica",
    "wellsfargo", "citibank", "amex", "irs", "ebay", "walmart",
    "dropbox", "steam", "roblox", "discord", "coinbase", "binance",
    "metamask", "opensea", "robinhood", "venmo", "cashapp",
]

URGENT_KEYWORDS = [
    "verify", "update", "confirm", "suspend", "login", "signin",
    "account", "secure", "security", "alert", "warning", "urgent",
    "limited", "expire", "validate", "authenticate", "recover",
]

URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "buff.ly",
    "short.link", "rb.gy", "shorturl.at", "cutt.ly", "is.gd", "tiny.cc",
}

# Tunnel / temporary-hosting services — legitimate for dev, but login pages on
# these are a strong phishing signal (attackers spin them up in seconds).
TUNNEL_SERVICES = {
    "serveo.net", "ngrok.io", "ngrok-free.app", "lhr.life",
    "localhost.run", "trycloudflare.com", "tunnelto.dev",
    "expose.dev", "bore.pub", "pinggy.io", "localtunnel.me",
    "pagekite.me", "telebit.cloud",
}

_LOGIN_PATHS = {"/login", "/signin", "/sign-in", "/auth", "/log-in", "/account/login"}


def _entropy(s: str) -> float:
    if not s:
        return 0.0
    freq = Counter(s)
    total = len(s)
    return -sum((c / total) * math.log2(c / total) for c in freq.values())


def check_url(url: str) -> dict:
    score = 0
    flags = []

    try:
        parsed = urlparse(url)
        domain = parsed.netloc.lower().split(":")[0]
        path = parsed.path.lower()
        query = parsed.query.lower()

        # tldextract correctly handles multi-part TLDs (.co.in, .co.uk, .com.au)
        # so "glassdoor.co.in" → domain="glassdoor", suffix="co.in" (not "co")
        ext = tldextract.extract(url)
        apex_name   = ext.domain or domain
        tld         = ext.suffix or ""
        raw_sub     = ext.subdomain or ""
        subdomains  = [s for s in raw_sub.split(".") if s and s != "www"]
        subdomain_str = ".".join(subdomains)
        apex_domain = f"{ext.domain}.{ext.suffix}" if ext.domain and ext.suffix else domain

        # 1. Suspicious TLD — check full suffix ("cyou") and registrable part ("in" of "co.in")
        tld_check = tld.split(".")[-1]
        matched_tld = tld if tld in SUSPICIOUS_TLDS else (tld_check if tld_check in SUSPICIOUS_TLDS else None)
        if matched_tld:
            pts = SUSPICIOUS_TLDS[matched_tld]
            score += pts
            flags.append(f"Suspicious TLD (.{matched_tld})")

        # 2. IP address as domain
        if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", domain):
            score += 75
            flags.append("IP address used as domain (not a real domain name)")

        # 3. Punycode / IDN homograph attack
        if "xn--" in domain:
            score += 55
            flags.append("Punycode domain — possible lookalike character attack")

        # 4. High-entropy domain name (looks randomly generated)
        ent = _entropy(apex_name)
        if ent > 3.5 and len(apex_name) >= 6:
            pts = min(35, int((ent - 3.5) * 15))
            score += pts
            flags.append(f"Domain name appears randomly generated (entropy {ent:.1f})")

        # 5. Alphanumeric mixing: letters+digits interspersed (e.g. luy4c7, abc3xyz)
        if re.search(r"[a-z]\d[a-z]|\d[a-z]\d", apex_name) and len(apex_name) <= 12:
            score += 20
            flags.append("Domain mixes letters and digits in random pattern")

        # 6. Excessive subdomains
        if len(subdomains) >= 3:
            score += 25
            flags.append(f"Excessive subdomain depth ({len(subdomains)} levels)")
        elif len(subdomains) == 2:
            score += 10

        # 7. Brand name used in subdomain but NOT in apex domain
        for brand in BRAND_KEYWORDS:
            if brand in subdomain_str and brand not in apex_name:
                score += 55
                flags.append(f"Brand '{brand}' impersonated in subdomain")
                break

        # 8. Brand name appears in URL path (impersonation of well-known service)
        for brand in BRAND_KEYWORDS:
            if brand in path:
                score += 15
                flags.append(f"Brand '{brand}' referenced in URL path")
                break

        # 9. No HTTPS
        if parsed.scheme == "http":
            score += 20
            flags.append("Unencrypted HTTP connection")

        # 10. Abnormally long URL
        url_len = len(url)
        if url_len > 120:
            score += 20
            flags.append(f"Unusually long URL ({url_len} characters)")
        elif url_len > 80:
            score += 8

        # 11. Digit-heavy apex domain (e.g. 12345678.com)
        digit_ratio = sum(c.isdigit() for c in apex_name) / max(len(apex_name), 1)
        if digit_ratio > 0.5:
            score += 30
            flags.append("Domain name is mostly numbers")

        # 12. Hyphen abuse (secure-paypal-login-update.com)
        hyphens = apex_name.count("-")
        if hyphens >= 3:
            score += 25
            flags.append(f"Excessive hyphens in domain name ({hyphens})")
        elif hyphens == 2:
            score += 10

        # 13. Multiple urgency keywords in path/query
        found_urgent = [kw for kw in URGENT_KEYWORDS if kw in path + query]
        if len(found_urgent) >= 3:
            score += 20
            flags.append(f"Multiple urgency keywords in URL: {', '.join(found_urgent[:3])}")
        elif len(found_urgent) >= 1:
            score += 5

        # 14. URL shortener (destination unknown)
        if apex_domain in URL_SHORTENERS:
            score += 30
            flags.append("URL shortener — real destination is hidden")

        # 15. Large numeric targeting ID (personalised phishing)
        if re.search(r"[?&]id=\d{8,}", url):
            score += 15
            flags.append("Large numeric targeting ID in URL query string")

        # 16. Double-extension trick (invoice.pdf.html)
        if re.search(r"\.(pdf|doc|docx|xls|zip|exe)\.(html?|php|asp)", path):
            score += 45
            flags.append("Double file extension trick (disguised file type)")

        # 17. Tunnel / temporary hosting service
        if apex_domain in TUNNEL_SERVICES:
            score += 100
            flags.append(f"Hosted on a temporary tunnel service ({apex_domain})")
            # Login page on a tunnel service is a strong phishing signal
            if any(path == lp or path.startswith(lp + "/") for lp in _LOGIN_PATHS):
                score += 35
                flags.append("Login page hosted on a temporary tunnel service")

    except Exception:
        pass

    return {
        "score": min(score, 100),
        "flags": flags,
        "layer": "url_rules",
    }
