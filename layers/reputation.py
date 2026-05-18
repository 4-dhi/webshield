"""
Layer 2 — External Reputation APIs
Checks Google Safe Browsing and URLhaus (abuse.ch) in parallel.
URLhaus requires no API key and covers both phishing and malware URLs.
Returns within ~4 seconds or on the first hit.
"""
import asyncio
import os

import httpx

GOOGLE_SB_KEY = os.getenv("GOOGLE_SAFE_BROWSING_KEY", "")

_THREAT_TYPES = [
    "MALWARE",
    "SOCIAL_ENGINEERING",
    "UNWANTED_SOFTWARE",
    "POTENTIALLY_HARMFUL_APPLICATION",
]


async def _google_safe_browsing(url: str, client: httpx.AsyncClient) -> dict:
    if not GOOGLE_SB_KEY:
        return {"score": 0, "flags": [], "layer": "google_safe_browsing", "skipped": True}
    try:
        payload = {
            "client": {"clientId": "webshield-ai", "clientVersion": "2.0"},
            "threatInfo": {
                "threatTypes": _THREAT_TYPES,
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": url}],
            },
        }
        resp = await client.post(
            f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={GOOGLE_SB_KEY}",
            json=payload,
            timeout=4.0,
        )
        if resp.status_code == 200:
            data = resp.json()
            if data.get("matches"):
                threat = data["matches"][0].get("threatType", "THREAT")
                return {
                    "score": 95,
                    "flags": [f"Google Safe Browsing: flagged as {threat}"],
                    "layer": "google_safe_browsing",
                }
    except Exception:
        pass
    return {"score": 0, "flags": [], "layer": "google_safe_browsing"}


async def _urlhaus(url: str, client: httpx.AsyncClient) -> dict:
    """
    URLhaus by abuse.ch — free, no API key, covers malware + phishing URLs.
    https://urlhaus-api.abuse.ch/
    """
    try:
        resp = await client.post(
            "https://urlhaus-api.abuse.ch/v1/url/",
            data={"url": url},
            headers={"User-Agent": "WebShieldAI/2.0"},
            timeout=4.0,
        )
        if resp.status_code == 200:
            data = resp.json()
            status = data.get("query_status", "")
            if status == "is_threat":
                threat = data.get("threat", "malware/phishing")
                tags = data.get("tags") or []
                tag_str = f" [{', '.join(tags[:3])}]" if tags else ""
                return {
                    "score": 90,
                    "flags": [f"URLhaus (abuse.ch): flagged as {threat}{tag_str}"],
                    "layer": "urlhaus",
                }
            # "no_results" means URL is not in their database — neutral, not safe
    except Exception:
        pass
    return {"score": 0, "flags": [], "layer": "urlhaus"}


async def check_reputation(url: str) -> dict:
    async with httpx.AsyncClient() as client:
        results = await asyncio.gather(
            _google_safe_browsing(url, client),
            _urlhaus(url, client),
            return_exceptions=True,
        )

    valid = [r for r in results if isinstance(r, dict)]
    top_score = max((r["score"] for r in valid), default=0)
    all_flags = [f for r in valid for f in r.get("flags", [])]

    return {
        "score": top_score,
        "flags": all_flags,
        "layer": "reputation",
        "details": valid,
    }
