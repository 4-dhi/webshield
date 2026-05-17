import os
from flask import Flask, request
from flask_cors import CORS
from checkphish import PhishingDetector

app = Flask(__name__)
CORS(app)

# Load model once at startup, not per request
detector = PhishingDetector(use_ml=True)


@app.route("/", methods=["POST"])
def analyze():
    data = request.get_json(silent=True) or {}
    url = data.get("url", "").strip()
    html = data.get("html", "").strip()

    if not url:
        return "⚠️ Missing URL parameter", 400

    try:
        results = detector.analyze_url(url, html=html if html else None)
        return "PHISHING" if results["is_suspicious"] else "SAFE"
    except Exception as e:
        return f"⚠️ Analysis error: {str(e)}", 500


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8000))
    app.run(host="0.0.0.0", port=port, debug=False)
