"""
WebShield.AI — FastAPI backend
Four-layer phishing detection pipeline:
  Layer 1  URL rule engine      (instant, no I/O)
  Layer 2  Reputation APIs      (Google Safe Browsing + PhishTank, parallel)
  Layer 3  Content analysis     (backend fetches page, no HTML from extension)
  Layer 4  ML model             (URL-feature RandomForest, hot-swappable)
"""
import asyncio
import ipaddress
import os
from urllib.parse import urlparse

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from database import init_db
from layers.content import fetch_and_analyze
from layers.reputation import check_reputation
from layers.url_rules import check_url
from model_manager import record_and_maybe_retrain

app = FastAPI(title="WebShield.AI", version="2.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)

# Layer weights for the final blended score
_WEIGHTS = {
    "url_rules":  1.0,
    "reputation": 3.0,   # authoritative databases — weighted highest
    "content":    1.5,
}


# ---------------------------------------------------------------------------
# Startup
# ---------------------------------------------------------------------------

@app.on_event("startup")
def on_startup() -> None:
    init_db()


# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------

class ScanRequest(BaseModel):
    url: str


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_PRIVATE_RANGES = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),  # link-local / AWS metadata
]


def _is_safe_target(url: str) -> bool:
    """Block SSRF targets: private IPs, localhost, file:// etc."""
    try:
        parsed = urlparse(url)
        if parsed.scheme not in ("http", "https"):
            return False
        host = parsed.hostname or ""
        if host in ("localhost", ""):
            return False
        try:
            ip = ipaddress.ip_address(host)
            if any(ip in net for net in _PRIVATE_RANGES):
                return False
        except ValueError:
            pass  # it's a hostname, not an IP — fine
        return True
    except Exception:
        return False


def _weighted_score(layers: dict) -> int:
    # Only include layers that actually found something.
    # Including zero-score layers in the average dilutes real signals —
    # a brand-new phishing URL will always score 0 in reputation databases.
    total_w = total_s = 0.0
    for name, weight in _WEIGHTS.items():
        if name in layers and isinstance(layers[name], dict):
            s = layers[name].get("score", 0)
            if s > 0:
                total_s += s * weight
                total_w += weight
    return int(total_s / total_w) if total_w else 0


def _build_response(verdict: str, score: int, layers: dict, url: str) -> dict:
    all_flags = [
        f
        for r in layers.values()
        if isinstance(r, dict)
        for f in r.get("flags", [])
    ]
    record_and_maybe_retrain(url, verdict, score, all_flags)
    return {
        "verdict": verdict,
        "score": score,
        "is_phishing": verdict == "PHISHING",
        "is_suspicious": verdict == "SUSPICIOUS",
        "flags": all_flags[:8],
        "layers_checked": list(layers.keys()),
    }


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.get("/")
def health() -> dict:
    return {"status": "ok", "service": "WebShield.AI", "version": "2.0"}


@app.get("/ping")
def ping() -> dict:
    return {"status": "ok"}


@app.post("/")
async def scan(req: ScanRequest) -> dict:
    url = req.url.strip()
    if not url:
        raise HTTPException(status_code=400, detail="URL is required")

    # Normalise scheme
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    # SSRF protection — reject private/local targets
    if not _is_safe_target(url):
        raise HTTPException(status_code=400, detail="URL target is not allowed")

    layers: dict = {}

    # ── Layer 1: URL rules (instant) ──────────────────────────────────────
    url_result = check_url(url)
    layers["url_rules"] = url_result

    # Early exit: URL alone is clearly malicious
    if url_result["score"] >= 85:
        return _build_response("PHISHING", url_result["score"], layers, url)

    # ── Layers 2 + 3 in parallel ──────────────────────────────────────────
    rep_result, content_result = await asyncio.gather(
        check_reputation(url),
        fetch_and_analyze(url),
        return_exceptions=True,
    )

    if isinstance(rep_result, dict):
        layers["reputation"] = rep_result
    if isinstance(content_result, dict):
        layers["content"] = content_result

    # Early exit: reputation database is certain
    if layers.get("reputation", {}).get("score", 0) >= 90:
        return _build_response("PHISHING", layers["reputation"]["score"], layers, url)

    final_score = _weighted_score(layers)
    if final_score >= 65:
        verdict = "PHISHING"
    elif final_score >= 40:
        verdict = "SUSPICIOUS"
    else:
        verdict = "SAFE"

    return _build_response(verdict, final_score, layers, url)


# ---------------------------------------------------------------------------
# Dev entrypoint
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import uvicorn
    port = int(os.environ.get("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)
