// WebShield.AI v2 — Extension popup logic
// The extension now sends only the URL; the backend fetches and analyses the page itself.
const BACKEND_URL = "https://webshield-6cz7.onrender.com"; // ← update after deploying

let currentState = "idle";

function setState(state, message = "", data = {}) {
  currentState = state;

  const container = document.getElementById("circleContainer");
  const button = document.getElementById("actionButton");
  const statusDisplay = document.getElementById("statusDisplay");
  const lockIcon = document.getElementById("lockIcon");
  const warningIcon = document.getElementById("warningIcon");
  const iconContainer = document.getElementById("iconContainer");
  const safeShield = document.getElementById("safeShield");
  const globeImage = document.getElementById("globeImage");
  const shieldImage = document.getElementById("shieldImage");
  const globeBase = document.getElementById("globeBase");
  const confidenceWrap = document.getElementById("confidenceWrap");
  const confidenceFill = document.getElementById("confidenceFill");
  const confidenceLabel = document.getElementById("confidenceLabel");
  const flagsList = document.getElementById("flagsList");

  // ── Reset all state ──────────────────────────────────────────────────────
  container.className = "circle-container active";
  statusDisplay.innerHTML = "";
  iconContainer.classList.remove("scanning");
  lockIcon.style.display = "none";
  warningIcon.classList.remove("show");
  warningIcon.style.display = "none";
  warningIcon.setAttribute("stroke", "#ff4444");
  safeShield.classList.remove("show");
  safeShield.style.display = "none";
  globeImage.style.display = "none";
  shieldImage.style.display = "none";
  globeBase.style.display = "block";
  confidenceWrap.style.display = "none";
  flagsList.style.display = "none";

  // ── Helpers ───────────────────────────────────────────────────────────────
  function showConfidence(score, gradient) {
    confidenceWrap.style.display = "block";
    confidenceFill.style.width = score + "%";
    confidenceFill.style.background = gradient;
    confidenceLabel.textContent = score + "% risk score";
  }

  function showFlags(flags) {
    if (!flags || flags.length === 0) return;
    flagsList.style.display = "block";
    flagsList.innerHTML = flags
      .slice(0, 3)
      .map((f) => `<li>${f}</li>`)
      .join("");
  }

  // ── States ────────────────────────────────────────────────────────────────
  switch (state) {
    case "idle":
      shieldImage.style.display = "block";
      button.textContent = "Check Your Site";
      button.disabled = false;
      break;

    case "analyzing":
      iconContainer.classList.add("scanning");
      globeImage.style.display = "block";
      globeBase.style.display = "none";
      button.disabled = true;
      statusDisplay.innerHTML =
        '<div class="analyzing-text"><span>Analyzing...</span><div class="spinner"></div></div>';
      break;

    case "safe":
      container.classList.add("safe-state");
      setTimeout(() => {
        safeShield.style.display = "block";
        safeShield.classList.add("show");
      }, 300);
      statusDisplay.innerHTML =
        '<div class="result-text safe-result">SAFE</div>';
      button.textContent = "Check Again";
      button.disabled = false;
      showConfidence(
        data.score || 5,
        "linear-gradient(90deg, #22c55e, #15803d)",
      );
      break;

    case "suspicious":
      container.classList.add("suspicious-state");
      warningIcon.setAttribute("stroke", "#f59e0b");
      warningIcon.style.display = "block";
      warningIcon.classList.add("show");
      statusDisplay.innerHTML =
        '<div class="result-text suspicious-result">SUSPICIOUS</div>';
      button.textContent = "Check Again";
      button.disabled = false;
      showConfidence(
        data.score || 50,
        "linear-gradient(90deg, #f59e0b, #d97706)",
      );
      showFlags(data.flags);
      break;

    case "phishing":
      container.classList.add("phishing-state");
      warningIcon.style.display = "block";
      warningIcon.classList.add("show");
      statusDisplay.innerHTML =
        '<div class="result-text phishing-result">PHISHING</div>';
      button.textContent = "Check Again";
      button.disabled = false;
      showConfidence(
        data.score || 80,
        "linear-gradient(90deg, #ff4444, #cc0000)",
      );
      showFlags(data.flags);
      break;

    case "error":
      lockIcon.style.display = "block";
      statusDisplay.innerHTML = `<div class="error-text">${message}</div>`;
      button.textContent = "Try Again";
      button.disabled = false;
      break;
  }
}

function analyzeWebsite() {
  setState("analyzing");

  chrome.tabs.query({ active: true, currentWindow: true }, function (tabs) {
    if (!tabs || tabs.length === 0) {
      setState("error", "No active tab found");
      return;
    }

    const url = tabs[0].url;

    if (
      url.startsWith("chrome://") ||
      url.startsWith("chrome-extension://") ||
      url.startsWith("edge://") ||
      url.startsWith("about:")
    ) {
      setState("error", "Cannot analyse browser system pages");
      return;
    }

    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 30000);

    // After 4s with no response, the server is likely cold-starting — tell the user
    const slowTimer = setTimeout(() => {
      const s = document.getElementById("statusDisplay");
      if (s) s.innerHTML = '<div class="analyzing-text"><span>Waking server...</span><div class="spinner"></div></div>';
    }, 4000);

    fetch(BACKEND_URL, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url }),
      signal: controller.signal,
    })
      .then((response) => {
        clearTimeout(timeoutId);
        clearTimeout(slowTimer);
        if (!response.ok) {
          throw new Error("Server responded with status: " + response.status);
        }
        return response.text();
      })
      .then((raw) => {
        let verdict, score, flags;

        // Try new JSON format first, then fall back to legacy plain-text
        try {
          const json = JSON.parse(raw);
          verdict = json.verdict;
          score = json.score;
          flags = json.flags || [];
        } catch {
          verdict = raw.includes("PHISHING")
            ? "PHISHING"
            : raw.includes("SAFE")
              ? "SAFE"
              : null;
          score = verdict === "PHISHING" ? 80 : verdict === "SAFE" ? 10 : 50;
          flags = [];
        }

        if (verdict === "SAFE") setState("safe", "", { score, flags });
        else if (verdict === "SUSPICIOUS")
          setState("suspicious", "", { score, flags });
        else if (verdict === "PHISHING")
          setState("phishing", "", { score, flags });
        else setState("error", "Unexpected response from server");
      })
      .catch((error) => {
        clearTimeout(timeoutId);
        clearTimeout(slowTimer);
        const msg =
          error.name === "AbortError"
            ? "Server took too long. Try again in a moment."
            : "Server connection failed. Error: " + error.message;
        setState("error", msg);
      });
  });
}

document.addEventListener("DOMContentLoaded", function () {
  setState("idle");
  document.getElementById("actionButton").addEventListener("click", analyzeWebsite);

  chrome.tabs.query({ active: true, currentWindow: true }, function (tabs) {
    const el = document.getElementById("urlDisplay");
    if (!tabs || tabs.length === 0) {
      if (el) el.textContent = "URL not available";
      return;
    }

    const tab = tabs[0];
    if (el) {
      el.textContent = tab.url.length > 45 ? tab.url.slice(0, 45) + "..." : tab.url;
    }

    // Show background scanner's cached result instantly — no button click needed
    chrome.storage.session.get(`scan_${tab.id}`, (data) => {
      const cached = data[`scan_${tab.id}`];
      if (!cached || cached.url !== tab.url) return;

      if (cached.verdict === "SAFE")
        setState("safe", "", { score: cached.score, flags: cached.flags });
      else if (cached.verdict === "SUSPICIOUS")
        setState("suspicious", "", { score: cached.score, flags: cached.flags });
      else if (cached.verdict === "PHISHING")
        setState("phishing", "", { score: cached.score, flags: cached.flags });
    });
  });
});
