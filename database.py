"""
SQLite persistence layer.
Stores prediction history and accumulates a training dataset over time.

Note: Render free tier uses an ephemeral filesystem — data resets on redeploy.
For persistence across deploys, set DB_PATH to a mounted disk path or
replace this module with a Supabase/PostgreSQL client.
"""
import json
import os
import sqlite3

DB_PATH = os.getenv("DB_PATH", "webshield.db")

_CREATE_PREDICTIONS = """
CREATE TABLE IF NOT EXISTS predictions (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    url        TEXT    NOT NULL,
    verdict    TEXT    NOT NULL,
    score      INTEGER,
    flags      TEXT,
    created_at TEXT    DEFAULT CURRENT_TIMESTAMP
)
"""

_CREATE_DATASET = """
CREATE TABLE IF NOT EXISTS dataset (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    url        TEXT    UNIQUE NOT NULL,
    label      INTEGER NOT NULL,
    source     TEXT    DEFAULT 'auto',
    created_at TEXT    DEFAULT CURRENT_TIMESTAMP
)
"""


def init_db() -> None:
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute(_CREATE_PREDICTIONS)
        conn.execute(_CREATE_DATASET)
        conn.commit()


def save_prediction(url: str, verdict: str, score: int, flags: list) -> int:
    """
    Persist a prediction result.
    High-confidence results are also added to the training dataset automatically.
    Returns the current training dataset size.
    """
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute(
            "INSERT INTO predictions (url, verdict, score, flags) VALUES (?,?,?,?)",
            (url, verdict, score, json.dumps(flags[:5])),
        )
        # Only auto-label when we're very confident — avoids poisoning the dataset
        if score >= 80 or score <= 15:
            label = 1 if verdict == "PHISHING" else 0
            conn.execute(
                "INSERT OR IGNORE INTO dataset (url, label, source) VALUES (?,?,?)",
                (url, label, "auto"),
            )
        conn.commit()
        count = conn.execute("SELECT COUNT(*) FROM dataset").fetchone()[0]
    return count


def get_training_data() -> list[tuple[str, int]]:
    with sqlite3.connect(DB_PATH) as conn:
        rows = conn.execute("SELECT url, label FROM dataset").fetchall()
    return list(rows)
