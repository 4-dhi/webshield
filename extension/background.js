// WebShield.AI — Background service worker
// Automatically scans every page the user visits.
// Results are stored in chrome.storage.session so the popup can read them instantly.

const BACKEND_URL = "https://webshield-6cz7.onrender.com"; // ← keep in sync with popup.js
const CACHE_TTL_MS = 30 * 60 * 1000;        // reuse result for 30 minutes
const SCAN_DEBOUNCE_MS = 800;                // wait before scanning (skip fast redirects)

const _debounceTimers = new Map(); // tabId → timer handle

// Silently wake the server when the service worker starts so it's warm
// before the user navigates to any page.
fetch(BACKEND_URL, { method: "GET" }).catch(() => {});

// Re-ping every 14 minutes to keep Render free-tier instance alive
setInterval(() => {
  fetch(BACKEND_URL, { method: "GET" }).catch(() => {});
}, 14 * 60 * 1000);

// ── Badge helpers ────────────────────────────────────────────────────────────

function setBadge(tabId, state) {
  const cfg = {
    scanning:   { text: "…",  color: "#6b7280" },
    safe:       { text: "✓",  color: "#22c55e" },
    suspicious: { text: "!",  color: "#f59e0b" },
    phishing:   { text: "✕",  color: "#ef4444" },
    error:      { text: "?",  color: "#6b7280" },
  }[state] || { text: "", color: "#6b7280" };

  chrome.action.setBadgeText({ text: cfg.text, tabId });
  chrome.action.setBadgeBackgroundColor({ color: cfg.color, tabId });
}

// ── Warning banner (injected into phishing pages) ───────────────────────────

async function injectWarningBanner(tabId, score, topFlag) {
  try {
    await chrome.scripting.executeScript({
      target: { tabId },
      func: (score, topFlag) => {
        if (document.getElementById("webshield-warning")) return;

        const bar = document.createElement("div");
        bar.id = "webshield-warning";
        bar.style.cssText = [
          "position:fixed", "top:0", "left:0", "right:0", "z-index:2147483647",
          "background:#dc2626", "color:#fff", "padding:10px 18px",
          "font:600 13px/1.4 system-ui,sans-serif",
          "display:flex", "align-items:center", "justify-content:space-between",
          "gap:12px", "box-shadow:0 2px 12px rgba(0,0,0,.4)",
        ].join(";");

        const msg = topFlag
          ? `⚠ WebShield.AI: Phishing detected — ${topFlag}`
          : `⚠ WebShield.AI: This site looks like a phishing page (${score}% risk)`;

        bar.innerHTML = `
          <span>${msg}</span>
          <span style="display:flex;gap:8px;flex-shrink:0">
            <button id="ws-leave"
              style="background:#fff;color:#dc2626;border:none;padding:5px 12px;
                     border-radius:4px;cursor:pointer;font-weight:700">
              ← Leave site
            </button>
            <button id="ws-dismiss"
              style="background:transparent;border:1px solid #fff;color:#fff;
                     padding:5px 12px;border-radius:4px;cursor:pointer">
              Dismiss
            </button>
          </span>`;

        document.body.prepend(bar);
        document.getElementById("ws-leave").onclick    = () => history.back();
        document.getElementById("ws-dismiss").onclick  = () => bar.remove();
      },
      args: [score, topFlag],
    });
  } catch {
    // Some pages block script injection — fail silently
  }
}

// ── Core scan ────────────────────────────────────────────────────────────────

async function scanTab(tabId, url) {
  const cacheKey = `scan_${tabId}`;

  // Return cached result if URL matches and is still fresh
  const stored = await chrome.storage.session.get(cacheKey);
  const cached = stored[cacheKey];
  if (cached && cached.url === url && (Date.now() - cached.timestamp) < CACHE_TTL_MS) {
    applyResult(tabId, cached);
    return;
  }

  setBadge(tabId, "scanning");

  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 30000);

    const resp = await fetch(BACKEND_URL, {
      method:  "POST",
      headers: { "Content-Type": "application/json" },
      body:    JSON.stringify({ url }),
      signal:  controller.signal,
    });
    clearTimeout(timeout);

    if (!resp.ok) throw new Error("HTTP " + resp.status);

    const data   = await resp.json();
    const result = {
      url,
      verdict:   data.verdict,
      score:     data.score,
      flags:     data.flags || [],
      timestamp: Date.now(),
    };

    await chrome.storage.session.set({ [cacheKey]: result });
    applyResult(tabId, result);

  } catch {
    setBadge(tabId, "error");
  }
}

function applyResult(tabId, result) {
  const { verdict, score, flags } = result;

  if (verdict === "PHISHING") {
    setBadge(tabId, "phishing");
    injectWarningBanner(tabId, score, flags[0] || null);
  } else if (verdict === "SUSPICIOUS") {
    setBadge(tabId, "suspicious");
  } else {
    setBadge(tabId, "safe");
  }
}

// ── Navigation listener ──────────────────────────────────────────────────────

chrome.webNavigation.onCompleted.addListener((details) => {
  if (details.frameId !== 0) return; // main frame only

  const { tabId, url } = details;
  if (!url.startsWith("http://") && !url.startsWith("https://")) return;

  // Debounce: cancel any pending scan for this tab (handles multi-step redirects)
  if (_debounceTimers.has(tabId)) {
    clearTimeout(_debounceTimers.get(tabId));
  }
  const timer = setTimeout(() => {
    _debounceTimers.delete(tabId);
    scanTab(tabId, url);
  }, SCAN_DEBOUNCE_MS);
  _debounceTimers.set(tabId, timer);
});

// Clear cache and badge when a tab is closed
chrome.tabs.onRemoved.addListener((tabId) => {
  chrome.storage.session.remove(`scan_${tabId}`);
  if (_debounceTimers.has(tabId)) {
    clearTimeout(_debounceTimers.get(tabId));
    _debounceTimers.delete(tabId);
  }
});
