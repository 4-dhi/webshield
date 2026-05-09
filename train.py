"""
train.py - Train the phishing detection ML model from dataset.txt

Usage:
    python train.py
    python train.py --dataset dataset.txt
    python train.py --dataset dataset.txt --model phishing_model.pkl

The script reads URL,LABEL pairs from the dataset file, extracts the same
30 features used by checkphish.py, trains a RandomForestClassifier, and
saves the model to phishing_model.pkl ready for use by checkphish.py.
"""

import sys
import io
import os
import argparse
import re
import numpy as np
import joblib
from urllib.parse import urlparse

# Windows UTF-8 fix
if sys.platform == 'win32':
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8', errors='replace')

from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, accuracy_score


# ---------------------------------------------------------------------------
# Feature extraction  (must stay in sync with checkphish.py extract_features)
# ---------------------------------------------------------------------------

def extract_features(url: str) -> np.ndarray:
    """Extract 30 URL-only features (no live HTTP request needed)."""
    features = []

    try:
        parsed = urlparse(url)
        domain = parsed.netloc.lower()
        path   = parsed.path.lower()

        # --- URL-based features (15) ---
        features.append(1 if parsed.scheme == 'https' else 0)          # 1  Has HTTPS
        features.append(len(url))                                        # 2  URL length
        features.append(domain.count('.'))                               # 3  Dots in domain
        features.append(domain.count('-'))                               # 4  Hyphens in domain
        features.append(domain.count('_'))                               # 5  Underscores in domain
        features.append(1 if re.search(r'\d', domain) else 0)           # 6  Digits in domain
        features.append(len(domain))                                     # 7  Domain length
        features.append(len(path))                                       # 8  Path length
        features.append(1 if '@' in url else 0)                         # 9  @ symbol
        features.append(1 if '//' in path else 0)                       # 10 Double slash in path
        features.append(url.count('?'))                                   # 11 Query params
        features.append(url.count('&'))                                   # 12 Ampersands
        features.append(1 if re.match(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', domain) else 0)  # 13 Is IP

        suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top', '.work']
        features.append(1 if any(domain.endswith(t) for t in suspicious_tlds) else 0)  # 14 Suspicious TLD
        features.append(1 if not all(ord(c) < 128 for c in domain) else 0)              # 15 Unicode/IDN

        # --- Content-based features filled with 0 (no live fetching) ---
        # These 15 slots match the `features.extend([0] * 15)` branch in
        # checkphish.py when soup is None.
        features.extend([0] * 15)

    except Exception as e:
        print(f"  [warn] Feature extraction failed for {url}: {e}")
        features.extend([0] * (30 - len(features)))

    # Ensure exactly 30 features
    while len(features) < 30:
        features.append(0)

    return np.array(features[:30])


# ---------------------------------------------------------------------------
# Dataset loader
# ---------------------------------------------------------------------------

def load_dataset(dataset_path: str):
    """Load URL,LABEL pairs from a dataset file, ignoring comment lines."""
    urls, labels = [], []

    if not os.path.exists(dataset_path):
        print(f"[ERROR] Dataset file not found: {dataset_path}")
        sys.exit(1)

    with open(dataset_path, 'r', encoding='utf-8', errors='replace') as f:
        for line_no, line in enumerate(f, 1):
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            parts = line.split(',')
            if len(parts) < 2:
                print(f"  [warn] Skipping malformed line {line_no}: {line}")
                continue
            url   = parts[0].strip()
            try:
                label = int(parts[-1].strip())
            except ValueError:
                print(f"  [warn] Skipping line {line_no} — invalid label: {parts[-1]}")
                continue
            urls.append(url)
            labels.append(label)

    return urls, labels


# ---------------------------------------------------------------------------
# Training pipeline
# ---------------------------------------------------------------------------

def train(dataset_path: str, model_path: str):
    print("=" * 60)
    print("  PHISHING DETECTION MODEL TRAINER")
    print("=" * 60)
    print(f"\n[*] Loading dataset: {dataset_path}")

    urls, labels = load_dataset(dataset_path)
    print(f"    Loaded {len(urls)} samples  "
          f"(legit: {labels.count(0)}, phishing: {labels.count(1)})")

    if len(urls) == 0:
        print("[ERROR] No valid samples found in dataset.")
        sys.exit(1)

    # ---- Feature extraction ------------------------------------------------
    print("\n[*] Extracting features (no live HTTP requests)...")
    X = np.array([extract_features(u) for u in urls])
    y = np.array(labels)
    print(f"    Feature matrix shape: {X.shape}")

    # ---- Train / test split ------------------------------------------------
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y if len(set(y)) > 1 else None
    )
    print(f"\n[*] Train samples: {len(X_train)}  |  Test samples: {len(X_test)}")

    # ---- Model training ----------------------------------------------------
    print("\n[*] Training RandomForestClassifier...")
    model = RandomForestClassifier(
        n_estimators=200,
        max_depth=None,
        min_samples_split=2,
        random_state=42,
        n_jobs=-1,
        verbose=1
    )
    model.fit(X_train, y_train)

    # ---- Evaluation --------------------------------------------------------
    y_pred = model.predict(X_test)
    acc    = accuracy_score(y_test, y_pred)

    print("\n" + "=" * 60)
    print("  MODEL PERFORMANCE")
    print("=" * 60)
    print(f"\n  Accuracy : {acc:.2%}")
    print("\nClassification Report:")
    print(classification_report(y_test, y_pred, target_names=['Legitimate', 'Phishing']))

    # ---- Feature importances (top 10) -------------------------------------
    feature_names = [
        'has_https', 'url_length', 'dot_count', 'hyphen_count', 'underscore_count',
        'digits_in_domain', 'domain_length', 'path_length', 'has_at', 'double_slash',
        'query_count', 'ampersand_count', 'is_ip', 'suspicious_tld', 'unicode_idn',
        'forms', 'password_fields', 'forms_with_validation', 'external_links',
        'total_images', 'external_images', 'total_scripts', 'external_scripts',
        'hidden_elements', 'iframes', 'urgency_keywords', 'meta_tags',
        'title_length', 'has_favicon', 'ssl_badges'
    ]
    importances = model.feature_importances_
    sorted_idx  = np.argsort(importances)[::-1]
    print("\nTop 10 Feature Importances:")
    for i in range(min(10, len(feature_names))):
        idx = sorted_idx[i]
        print(f"  {i+1:>2}. {feature_names[idx]:<25} {importances[idx]:.4f}")

    # ---- Save model --------------------------------------------------------
    joblib.dump(model, model_path)
    print(f"\n[+] Model saved to: {model_path}")
    print("[+] Training complete! You can now run checkphish.py.")
    print("=" * 60)

    return acc


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description='Train the phishing detection ML model from dataset.txt'
    )
    parser.add_argument(
        '--dataset', default='dataset.txt',
        help='Path to the dataset file (default: dataset.txt)'
    )
    parser.add_argument(
        '--model', default='phishing_model.pkl',
        help='Output model file path (default: phishing_model.pkl)'
    )
    args = parser.parse_args()

    train(args.dataset, args.model)


if __name__ == '__main__':
    main()