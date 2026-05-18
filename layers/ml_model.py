"""
Layer 4 — Machine Learning Model
URL-feature-only classifier (15 features, no HTTP requests needed).
Supports atomic hot-swap for zero-downtime retraining.
"""
import math
import re
import threading
from collections import Counter
from urllib.parse import urlparse

import tldextract

import joblib
import numpy as np

_lock = threading.Lock()
_model = None

SUSPICIOUS_TLDS = {
    "cyou", "xyz", "tk", "ml", "cf", "gq", "ga", "top", "click", "link",
    "online", "site", "pw", "ws", "cc", "su", "icu", "buzz", "vip", "loan",
    "win", "download", "accountant", "date", "racing", "party", "review",
    "faith", "cricket", "science", "work", "trade",
}

_URGENT_KW = [
    "verify", "update", "confirm", "suspend", "login", "signin",
    "account", "secure", "security", "alert", "warning", "validate",
]


def _entropy(s: str) -> float:
    if not s:
        return 0.0
    freq = Counter(s)
    total = len(s)
    return -sum((c / total) * math.log2(c / total) for c in freq.values())


def extract_features(url: str) -> list:
    """
    15 URL-based features — deterministic, no network access.
    Must stay in sync with the training pipeline in train.py.
    """
    try:
        parsed = urlparse(url)
        domain = parsed.netloc.lower().split(":")[0]
        path = parsed.path.lower()
        query = parsed.query.lower()

        # tldextract handles multi-part TLDs (.co.in, .co.uk, .com.au) correctly
        ext    = tldextract.extract(url)
        apex   = ext.domain or domain
        tld    = ext.suffix or ""
        raw_sub = ext.subdomain or ""
        subdomains = [s for s in raw_sub.split(".") if s and s != "www"]

        tld_check = tld.split(".")[-1]
        sus_tld = int(tld in SUSPICIOUS_TLDS or tld_check in SUSPICIOUS_TLDS)

        return [
            len(url),
            len(domain),
            int(parsed.scheme != "https"),
            int(bool(re.match(r"^\d{1,3}(\.\d{1,3}){3}$", domain.split(":")[0]))),
            round(_entropy(apex), 4),
            sus_tld,
            apex.count("-"),
            len(subdomains),
            round(sum(c.isdigit() for c in apex) / max(len(apex), 1), 4),
            int("xn--" in domain),
            sum(1 for kw in _URGENT_KW if kw in path + query),
            len(path.split("/")) - 1,
            len(query),
            int(bool(re.search(r"[?&]id=\d{8,}", url))),
            int(bool(re.search(r"[a-z]\d[a-z]|\d[a-z]\d", apex)) and len(apex) <= 12),
        ]
    except Exception:
        return [0] * 15


def load_model(path: str = "phishing_model.pkl") -> bool:
    """Load a saved model; return False if file is missing or feature-incompatible."""
    global _model
    try:
        m = joblib.load(path)
        # Validate feature count by running a test prediction
        test = np.array(extract_features("https://example.com")).reshape(1, -1)
        m.predict_proba(test)
        with _lock:
            _model = m
        return True
    except Exception:
        return False


def hot_swap(new_model) -> None:
    """Atomically replace the model — no request will see an inconsistent state."""
    with _lock:
        global _model
        _model = new_model


def get_model():
    with _lock:
        return _model


def predict(url: str) -> dict:
    model = get_model()
    if model is None:
        return {"score": 0, "flags": [], "layer": "ml", "skipped": True}

    try:
        features = np.array(extract_features(url)).reshape(1, -1)
        prob = model.predict_proba(features)[0]
        phish_prob = float(prob[1]) if len(prob) > 1 else float(prob[0])
        score = int(phish_prob * 100)
        flags = []
        if phish_prob >= 0.75:
            flags.append(f"ML model: {phish_prob:.0%} phishing probability")
        return {"score": score, "flags": flags, "layer": "ml", "confidence": phish_prob}
    except Exception as e:
        return {"score": 0, "flags": [], "layer": "ml", "error": str(e)[:60]}
