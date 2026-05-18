"""
Model lifecycle management.
- Trains a fresh model at startup (ensures feature compatibility).
- Records every prediction to SQLite.
- Background-retrains after every RETRAIN_EVERY high-confidence new samples.
- Hot-swaps the model atomically so no request ever sees a broken state.
"""
import os
import threading

import joblib
import numpy as np
from sklearn.ensemble import RandomForestClassifier

from database import get_training_data, save_prediction
from layers.ml_model import extract_features, hot_swap

MODEL_PATH = "phishing_model.pkl"
DATASET_PATH = "dataset.txt"
RETRAIN_EVERY = 50

_retrain_lock = threading.Lock()
_new_sample_count = 0


# ---------------------------------------------------------------------------
# Dataset loading
# ---------------------------------------------------------------------------

def _load_base_dataset() -> list[tuple[str, int]]:
    """Read dataset.txt — the hand-curated baseline."""
    rows: list[tuple[str, int]] = []
    if not os.path.exists(DATASET_PATH):
        return rows
    with open(DATASET_PATH, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#") or line.lower().startswith("url"):
                continue
            parts = line.rsplit(",", 1)
            if len(parts) == 2:
                try:
                    rows.append((parts[0].strip(), int(parts[1].strip())))
                except ValueError:
                    pass
    return rows


def _merge_datasets() -> list[tuple[str, int]]:
    """Merge base dataset + dynamically accumulated SQLite data, deduplicating by URL."""
    seen: dict[str, int] = {}
    for url, label in _load_base_dataset() + get_training_data():
        seen[url] = label
    return list(seen.items())


# ---------------------------------------------------------------------------
# Training
# ---------------------------------------------------------------------------

def _fit(data: list[tuple[str, int]]) -> RandomForestClassifier | None:
    if len(data) < 20:
        return None
    X = np.array([extract_features(url) for url, _ in data])
    y = np.array([label for _, label in data])
    if len(set(y.tolist())) < 2:
        return None
    clf = RandomForestClassifier(n_estimators=200, random_state=42, n_jobs=-1)
    clf.fit(X, y)
    return clf


def startup_train() -> bool:
    """
    Always train a fresh model at startup so it is guaranteed to match the
    current feature extractor in layers/ml_model.py.
    Fast: 190 samples + URL-only features takes < 5 seconds.
    """
    data = _merge_datasets()
    model = _fit(data)
    if model is None:
        print("[WebShield] Not enough training data — ML layer disabled")
        return False
    hot_swap(model)
    joblib.dump(model, MODEL_PATH)
    n_phish = sum(1 for _, l in data if l == 1)
    n_safe = len(data) - n_phish
    print(f"[WebShield] Startup model trained: {len(data)} samples ({n_safe} safe, {n_phish} phishing)")
    return True


def _background_retrain() -> None:
    try:
        data = _merge_datasets()
        model = _fit(data)
        if model is None:
            return
        hot_swap(model)
        joblib.dump(model, MODEL_PATH)
        print(f"[WebShield] Background retrain complete — {len(data)} samples")
    except Exception as e:
        print(f"[WebShield] Retrain error: {e}")
    finally:
        _retrain_lock.release()


# ---------------------------------------------------------------------------
# Per-request recording
# ---------------------------------------------------------------------------

def record_and_maybe_retrain(url: str, verdict: str, score: int, flags: list) -> None:
    global _new_sample_count
    save_prediction(url, verdict, score, flags)
    # Only count high-confidence results toward the retrain threshold
    if score >= 80 or score <= 15:
        _new_sample_count += 1
    if _new_sample_count >= RETRAIN_EVERY:
        if _retrain_lock.acquire(blocking=False):
            _new_sample_count = 0
            thread = threading.Thread(target=_background_retrain, daemon=True)
            thread.start()
