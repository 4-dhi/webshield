"""
Standalone training script.
Reads dataset.txt and any SQLite-accumulated data, trains a RandomForest
on URL features, saves to phishing_model.pkl.

Usage:
    python train.py
    python train.py --dataset my_dataset.txt --output my_model.pkl
"""
import argparse
import os
import sys

import joblib
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report
from sklearn.model_selection import train_test_split

sys.path.insert(0, os.path.dirname(__file__))
from layers.ml_model import extract_features


def load_dataset(path: str) -> list[tuple[str, int]]:
    rows: list[tuple[str, int]] = []
    with open(path, encoding="utf-8") as f:
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


def main() -> None:
    parser = argparse.ArgumentParser(description="Train the WebShield URL classifier")
    parser.add_argument("--dataset", default="dataset.txt", help="Path to CSV dataset (url,label)")
    parser.add_argument("--output",  default="phishing_model.pkl", help="Output model path")
    args = parser.parse_args()

    print(f"Loading dataset: {args.dataset}")
    data = load_dataset(args.dataset)
    if not data:
        print("ERROR: No data loaded. Check dataset format (url,label per line).")
        sys.exit(1)

    n_phish = sum(1 for _, l in data if l == 1)
    n_safe  = len(data) - n_phish
    print(f"  {len(data)} total samples  |  {n_safe} legitimate  |  {n_phish} phishing")

    print("Extracting URL features (no HTTP requests needed)...")
    X = np.array([extract_features(url) for url, _ in data])
    y = np.array([label for _, label in data])

    if len(set(y.tolist())) < 2:
        print("ERROR: Dataset must contain both phishing and legitimate samples.")
        sys.exit(1)

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, stratify=y, random_state=42
    )

    print(f"Training RandomForestClassifier (200 trees) on {len(X_train)} samples...")
    clf = RandomForestClassifier(n_estimators=200, random_state=42, n_jobs=-1)
    clf.fit(X_train, y_train)

    print("\nTest set performance:")
    print(classification_report(y_test, clf.predict(X_test), target_names=["Legitimate", "Phishing"]))

    joblib.dump(clf, args.output)
    print(f"Model saved → {args.output}")


if __name__ == "__main__":
    main()
