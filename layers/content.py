"""
Layer 3 — Content Analysis
The backend fetches the page itself (never sent from the extension).
Extracts phishing signals from the live page.
"""
import re
from urllib.parse import urljoin, urlparse

import httpx
from bs4 import BeautifulSoup

_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/120.0.0.0 Safari/537.36"
    ),
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.5",
}

_BRANDS = [
    "paypal", "apple", "microsoft", "google", "amazon", "netflix",
    "facebook", "instagram", "twitter", "linkedin", "chase", "bank of america",
    "wells fargo", "citibank", "american express", "irs", "ebay", "walmart",
    "coinbase", "binance", "steam", "roblox", "discord", "metamask",
]

_LEGIT_EMBEDS = {
    "youtube.com", "google.com", "gstatic.com", "twitter.com",
    "facebook.com", "recaptcha.net", "maps.googleapis.com",
}

_OBFUSCATION_PATTERNS = [
    "eval(", "unescape(", "String.fromCharCode(", "document.write(unescape",
    "atob(", "\\x", "\\u00",
]

TUNNEL_SERVICES = {
    "serveo.net", "ngrok.io", "ngrok-free.app", "lhr.life",
    "localhost.run", "trycloudflare.com", "tunnelto.dev",
    "expose.dev", "bore.pub", "pinggy.io", "localtunnel.me",
    "pagekite.me", "telebit.cloud",
}

_URGENCY_PHRASES = [
    "your account will be suspended",
    "verify your account immediately",
    "unusual sign-in activity",
    "click here to avoid",
    "your account has been compromised",
    "update your payment information",
    "confirm your identity now",
    "your account has been locked",
    "limited time to respond",
    "act immediately to prevent",
]


async def fetch_and_analyze(url: str) -> dict:
    score = 0
    flags = []

    # Fetch the live page from the backend
    try:
        async with httpx.AsyncClient(
            follow_redirects=True,
            max_redirects=5,
            headers=_HEADERS,
            timeout=8.0,
        ) as client:
            resp = await client.get(url)
            html = resp.text[:500_000]   # cap at 500 KB
            final_url = str(resp.url)
            status_code = resp.status_code
    except httpx.SSLError:
        return {
            "score": 30,
            "flags": ["SSL certificate error — connection may be unsafe"],
            "layer": "content",
        }
    except Exception as e:
        # Can't fetch — skip content analysis, don't penalise
        return {"score": 0, "flags": [], "layer": "content", "error": str(e)[:80]}

    if status_code >= 500:
        return {"score": 5, "flags": ["Server error when loading the page"], "layer": "content"}

    try:
        soup = BeautifulSoup(html, "lxml")
        orig_domain = urlparse(url).netloc.lower().removeprefix("www.")
        final_domain = urlparse(final_url).netloc.lower().removeprefix("www.")

        # 1. Redirect to a completely different domain
        if orig_domain and final_domain and orig_domain != final_domain:
            if not final_domain.endswith("." + orig_domain) and not orig_domain.endswith("." + final_domain):
                score += 25
                flags.append(f"Redirects from {orig_domain} → {final_domain}")

        # 2. Form submitting credentials to an external domain
        for form in soup.find_all("form"):
            action = form.get("action", "").strip()
            if action and not action.startswith("#"):
                action_domain = urlparse(urljoin(final_url, action)).netloc.lower().removeprefix("www.")
                if action_domain and action_domain != final_domain:
                    score += 50
                    flags.append(f"Login form submits to external domain: {action_domain}")
                    break

        # 3. Password field checks
        has_password = bool(soup.find("input", {"type": "password"}))
        if has_password and urlparse(url).scheme != "https":
            score += 40
            flags.append("Password field on unencrypted HTTP page")

        # 3a. Login form on a tunnel/temporary hosting service
        is_tunnel = any(ts in final_domain for ts in TUNNEL_SERVICES)
        if has_password and is_tunnel:
            score += 45
            flags.append("Login form on temporary tunnel service — rarely legitimate in production")

        # 4. Page title claims to be a known brand but domain doesn't match
        title_tag = soup.find("title")
        if title_tag:
            title = title_tag.get_text().lower()
            for brand in _BRANDS:
                if brand in title:
                    brand_key = brand.replace(" ", "").replace("of", "")
                    if brand_key not in final_domain.replace(".", ""):
                        score += 35
                        flags.append(
                            f"Page claims to be '{brand.title()}' but domain is '{final_domain}'"
                        )
                        break

        # 5. Favicon loaded from a different (legitimate) domain — stolen branding
        favicon = soup.find("link", rel=lambda r: r and "icon" in " ".join(r).lower())
        if favicon:
            fav_href = favicon.get("href", "")
            if fav_href and not fav_href.startswith("data:"):
                fav_domain = urlparse(urljoin(final_url, fav_href)).netloc.lower().removeprefix("www.")
                if fav_domain and fav_domain != final_domain and "." in fav_domain:
                    score += 20
                    flags.append(f"Favicon loaded from {fav_domain} (stolen branding)")

        # 6. Heavily obfuscated JavaScript
        script_text = " ".join(s.get_text() for s in soup.find_all("script"))
        obf_hits = sum(1 for p in _OBFUSCATION_PATTERNS if p in script_text)
        if obf_hits >= 3:
            score += 25
            flags.append("Heavy JavaScript obfuscation detected")
        elif obf_hits >= 2:
            score += 12

        # 7. External iframe pointing to unknown domain (not a known embed)
        for iframe in soup.find_all("iframe"):
            src = iframe.get("src", "")
            if src and not src.startswith(("#", "about:", "javascript:")):
                iframe_domain = urlparse(urljoin(final_url, src)).netloc.lower().removeprefix("www.")
                if iframe_domain and iframe_domain != final_domain:
                    if not any(legit in iframe_domain for legit in _LEGIT_EMBEDS):
                        score += 20
                        flags.append(f"Suspicious external iframe: {iframe_domain}")
                        break

        # 8. Urgency language in page body text
        body_text = soup.get_text(" ", strip=True).lower()
        for phrase in _URGENCY_PHRASES:
            if phrase in body_text:
                score += 15
                flags.append(f'Urgency language found: "{phrase[:50]}"')
                break

        # 9. Login form present but no privacy policy or contact page
        all_links = [a.get("href", "").lower() for a in soup.find_all("a", href=True)]
        has_policy = any("privacy" in l or "terms" in l or "legal" in l for l in all_links)
        has_contact = any("contact" in l or "about" in l for l in all_links)
        if has_password and not has_policy and not has_contact:
            score += 10
            flags.append("Login form with no privacy policy or contact links")

        # 10. Meta-refresh redirect to another URL
        meta_refresh = soup.find("meta", attrs={"http-equiv": re.compile(r"refresh", re.I)})
        if meta_refresh:
            content = meta_refresh.get("content", "")
            if "url=" in content.lower():
                score += 20
                flags.append("Meta-refresh redirect found (auto-redirects to another page)")

    except Exception:
        pass

    return {
        "score": min(score, 100),
        "flags": flags,
        "layer": "content",
    }
