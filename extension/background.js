// WebShield.AI — Background Service Worker
// Orchestrates phishing scanning, network blocking, stats, and security.

importScripts(
  "tracker.js",
  "stats.js",
  "rules-engine.js",
  "security.js",
  "adblock.js",
);

const BACKEND_URL = "https://webshield-6cz7.onrender.com";
const CACHE_TTL_MS = 30 * 60 * 1000;
const SCAN_DEBOUNCE_MS = 800;

const _debounceTimers = new Map();
let adBlockDebug = false;
let dnrDebugActive = false;

fetch(BACKEND_URL, { method: "GET" }).catch(() => {});
setInterval(() => fetch(BACKEND_URL, { method: "GET" }).catch(() => {}), 14 * 60 * 1000);

// ── Badge helpers ────────────────────────────────────────────────────────────

function setBadge(tabId, state) {
  const cfg = {
    scanning: { text: "…", color: "#6b7280" },
    safe: { text: "✓", color: "#22c55e" },
    suspicious: { text: "!", color: "#f59e0b" },
    phishing: { text: "✕", color: "#ef4444" },
    error: { text: "?", color: "#6b7280" },
  }[state] || { text: "", color: "#6b7280" };

  chrome.action.setBadgeText({ text: cfg.text, tabId });
  chrome.action.setBadgeBackgroundColor({ color: cfg.color, tabId });
}

// ── Phishing warning banner ────────────────────────────────────────────────────

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
          "font:600 13px/1.4 system-ui,sans-serif", "display:flex",
          "align-items:center", "justify-content:space-between", "gap:12px",
          "box-shadow:0 2px 12px rgba(0,0,0,.4)",
        ].join(";");
        const msg = topFlag
          ? `⚠ WebShield.AI: Phishing detected — ${topFlag}`
          : `⚠ WebShield.AI: This site looks like a phishing page (${score}% risk)`;
        bar.innerHTML = `<span>${msg}</span>
          <span style="display:flex;gap:8px;flex-shrink:0">
            <button id="ws-leave" style="background:#fff;color:#dc2626;border:none;padding:5px 12px;border-radius:4px;cursor:pointer;font-weight:700">← Leave site</button>
            <button id="ws-dismiss" style="background:transparent;border:1px solid #fff;color:#fff;padding:5px 12px;border-radius:4px;cursor:pointer">Dismiss</button>
          </span>`;
        document.body.prepend(bar);
        document.getElementById("ws-leave").onclick = () => history.back();
        document.getElementById("ws-dismiss").onclick = () => bar.remove();
      },
      args: [score, topFlag],
    });
  } catch { /* injection blocked */ }
}

// ── Phishing scan ──────────────────────────────────────────────────────────────

async function scanTab(tabId, url) {
  const cacheKey = `scan_${tabId}`;
  const stored = await chrome.storage.session.get(cacheKey);
  const cached = stored[cacheKey];
  if (cached && cached.url === url && Date.now() - cached.timestamp < CACHE_TTL_MS) {
    applyResult(tabId, cached);
    return;
  }
  setBadge(tabId, "scanning");
  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 30000);
    const resp = await fetch(BACKEND_URL, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url }),
      signal: controller.signal,
    });
    clearTimeout(timeout);
    if (!resp.ok) throw new Error("HTTP " + resp.status);
    const data = await resp.json();
    const result = {
      url, verdict: data.verdict, score: data.score,
      flags: data.flags || [], timestamp: Date.now(),
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
    wsIncrementStats(tabId, { type: "phishing" });
    injectWarningBanner(tabId, score, flags[0] || null);
  } else if (verdict === "SUSPICIOUS") {
    setBadge(tabId, "suspicious");
  } else {
    setBadge(tabId, "safe");
  }
}

function adLog() {
  if (adBlockDebug) console.log("[WebShield AdBlock]", ...arguments);
}

// ── Navigation listeners ───────────────────────────────────────────────────────

chrome.webNavigation.onCompleted.addListener((details) => {
  if (details.frameId !== 0) return;
  const { tabId, url } = details;
  if (!url.startsWith("http://") && !url.startsWith("https://")) return;
  if (_debounceTimers.has(tabId)) clearTimeout(_debounceTimers.get(tabId));
  const timer = setTimeout(() => {
    _debounceTimers.delete(tabId);
    scanTab(tabId, url);
  }, SCAN_DEBOUNCE_MS);
  _debounceTimers.set(tabId, timer);
});

chrome.tabs.onRemoved.addListener((tabId) => {
  chrome.storage.session.remove(`scan_${tabId}`);
  chrome.storage.session.remove(`tab_stats_${tabId}`).catch(() => {});
  if (_debounceTimers.has(tabId)) {
    clearTimeout(_debounceTimers.get(tabId));
    _debounceTimers.delete(tabId);
  }
});

chrome.webNavigation.onBeforeNavigate.addListener((details) => {
  if (details.frameId !== 0) return;
  chrome.storage.session.remove(`tab_stats_${details.tabId}`).catch(() => {});
});

// ── Ad blocker initialization ──────────────────────────────────────────────────

chrome.storage.local.get({ adBlockEnabled: true, adBlockDebug: false, youtubeAdBlockEnabled: false }, (res) => {
  adBlockDebug = !!res.adBlockDebug;

  // First, handle YouTube rules based on toggle state
  if (!res.youtubeAdBlockEnabled) {
    console.log("[WebShield] YouTube blocker disabled on startup");
    disableYoutubeRules().then(() => {
      adLog("YouTube rules disabled on startup");
    });
  }

  // Then handle main ad blocker
  if (res.adBlockEnabled) {
    console.log("[WebShield] Ad blocker enabled on startup");
    enableAdBlocker().then(() => {
      adLog("Ad blocker enabled");
      wsOptimizeRules().then((r) => adLog("Rules optimized:", r));
    });
  } else {
    console.log("[WebShield] Ad blocker disabled on startup");
    disableAdBlocker();
  }

  // Finally, enable YouTube rules if toggle is ON
  if (res.youtubeAdBlockEnabled) {
    console.log("[WebShield] YouTube blocker enabled on startup");
    enableYoutubeRules().then(() => {
      adLog("YouTube rules enabled");
    });
  }
});

chrome.storage.onChanged.addListener((changes, area) => {
  if (area !== "local") return;
  if (changes.adBlockEnabled) {
    if (changes.adBlockEnabled.newValue) {
      console.log("[WebShield] Ad blocker enabled via toggle");
      enableAdBlocker().then(() => {
        chrome.storage.local.get({ youtubeAdBlockEnabled: false }, (res) => {
          if (!res.youtubeAdBlockEnabled) {
            console.log("[WebShield] YouTube rules disabled (ad blocker enabled but YouTube toggle off)");
            disableYoutubeRules().then(() => {
              adLog("YouTube rules disabled");
            });
          }
        });
      });
    } else {
      console.log("[WebShield] Ad blocker disabled via toggle");
      disableAdBlocker();
    }
  }
  if (changes.adBlockDebug) adBlockDebug = !!changes.adBlockDebug.newValue;
  if (changes.youtubeAdBlockEnabled) {
    if (changes.youtubeAdBlockEnabled.newValue) {
      console.log("[WebShield] YouTube blocker enabled via toggle");
      enableYoutubeRules().then(() => {
        adLog("YouTube rules enabled");
      });
    } else {
      console.log("[WebShield] YouTube blocker disabled via toggle");
      disableYoutubeRules().then(() => {
        adLog("YouTube rules disabled");
      });
    }
  }
});

wsInitSecurityListeners();

// ── Network block tracking ───────────────────────────────────────────────────────

chrome.webRequest.onBeforeRequest.addListener(
  (details) => {
    if (dnrDebugActive) return;
    if (details.url.startsWith("chrome-extension://")) return;
    chrome.storage.local.get({ adBlockEnabled: true, youtubeAdBlockEnabled: false }, (res) => {
      if (!res.adBlockEnabled) return;
      const classification = wsClassifyRequest(details.url, null, res.youtubeAdBlockEnabled);
      if (classification.isAd || classification.isTracker || classification.isMalware) {
        wsRecordBlock(details.tabId, classification, "webRequest", details.requestId);
      }
    });
  },
  { urls: ["<all_urls>"] },
);

if (
  chrome.declarativeNetRequest &&
  chrome.declarativeNetRequest.onRuleMatchedDebug &&
  typeof chrome.declarativeNetRequest.onRuleMatchedDebug.addListener === "function"
) {
  dnrDebugActive = true;
  chrome.declarativeNetRequest.onRuleMatchedDebug.addListener((info) => {
    const tabId = info.request && info.request.tabId;
    if (tabId === undefined || tabId < 0) return;
    const classification = wsClassifyRequest(info.request.url || "");
    wsRecordBlock(tabId, classification, "DNR", info.request.requestId);
  });
}

// ── Message router ───────────────────────────────────────────────────────────────

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (!message || !message.action) return false;
  const tabId = sender.tab && sender.tab.id;

  switch (message.action) {
    case "cosmeticHide":
      if (tabId >= 0) {
        chrome.storage.local.get({ adBlockEnabled: true }, (res) => {
          if (res.adBlockEnabled) wsIncrementStats(tabId, { type: "cosmetic" });
        });
      }
      sendResponse({ ok: true });
      return true;

    case "antiAdblockRemoved":
      if (tabId >= 0) wsIncrementStats(tabId, { type: "antiAdblock" });
      sendResponse({ ok: true });
      return true;

    case "blockPopup":
    case "blockRedirect":
      if (tabId >= 0) wsIncrementStats(tabId, { type: "ad" });
      sendResponse({ ok: true });
      return true;

    case "suspiciousForm":
      if (tabId >= 0) wsIncrementStats(tabId, { type: "phishing" });
      sendResponse({ ok: true });
      return true;

    case "pageLoadTime":
      if (message.ms) {
        chrome.storage.local.get({ pageLoadSavedMs: 0 }, (res) => {
          const saved = (res.pageLoadSavedMs || 0) + Math.min(message.ms * 0.15, 500);
          chrome.storage.local.set({ pageLoadSavedMs: Math.round(saved) });
        });
      }
      sendResponse({ ok: true });
      return true;

    case "getDnrDiagnostics":
      getDnrDiagnostics().then(sendResponse);
      return true;

    case "getStats":
      wsGetStats(tabId).then(sendResponse);
      return true;

    case "setAdBlockDebug":
      setAdBlockDebug(message.enabled).then(() => {
        adBlockDebug = !!message.enabled;
        sendResponse({ ok: true });
      });
      return true;

    case "optimizeRules":
      optimizeRules().then(sendResponse);
      return true;

    default:
      return false;
  }
});
