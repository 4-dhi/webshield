// WebShield.AI — Background service worker
// Automatically scans every page the user visits.
// Results are stored in chrome.storage.session so the popup can read them instantly.

importScripts("adblock.js");

const BACKEND_URL = "https://webshield-6cz7.onrender.com"; // ← keep in sync with popup.js
const CACHE_TTL_MS = 30 * 60 * 1000; // reuse result for 30 minutes
const SCAN_DEBOUNCE_MS = 800; // wait before scanning (skip fast redirects)

const _debounceTimers = new Map(); // tabId → timer handle

// Silently wake the server when the service worker starts so it's warm
// before the user navigates to any page.
fetch(BACKEND_URL, { method: "GET" }).catch(() => {});

// Re-ping every 14 minutes to keep Render free-tier instance alive
setInterval(
  () => {
    fetch(BACKEND_URL, { method: "GET" }).catch(() => {});
  },
  14 * 60 * 1000,
);

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
          "position:fixed",
          "top:0",
          "left:0",
          "right:0",
          "z-index:2147483647",
          "background:#dc2626",
          "color:#fff",
          "padding:10px 18px",
          "font:600 13px/1.4 system-ui,sans-serif",
          "display:flex",
          "align-items:center",
          "justify-content:space-between",
          "gap:12px",
          "box-shadow:0 2px 12px rgba(0,0,0,.4)",
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
        document.getElementById("ws-leave").onclick = () => history.back();
        document.getElementById("ws-dismiss").onclick = () => bar.remove();
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
  if (
    cached &&
    cached.url === url &&
    Date.now() - cached.timestamp < CACHE_TTL_MS
  ) {
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
      url,
      verdict: data.verdict,
      score: data.score,
      flags: data.flags || [],
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
  chrome.storage.session.remove(`tab_stats_${tabId}`).catch(() => {});
  if (_debounceTimers.has(tabId)) {
    clearTimeout(_debounceTimers.get(tabId));
    _debounceTimers.delete(tabId);
  }
});

// ── Ad Blocker Logic ──────────────────────────────────────────────────────────

const AD_PATTERNS = [
  "doubleclick.net",
  "googlesyndication.com",
  "googleadservices.com",
  "googletagservices.com",
  "adservice.google.com",
  "pagead2.googlesyndication.com",
  "securepubads.g.doubleclick.net",
  "adnxs.com",
  "adsrvr.org",
  "adtech.de",
  "adform.net",
  "adroll.com",
  "outbrain.com",
  "taboola.com",
  "criteo.com",
  "criteo.net",
  "amazon-adsystem.com",
  "amazonadsystem.com",
  "popads.net",
  "popcash.net",
  "carbonads.net",
  "buyads.co",
  "buysellads.com",
  "advertising.com",
  "bidswitch.net",
  "pubmatic.com",
  "rubiconproject.com",
  "openx.net",
  "casalemedia.com",
  "33across.com",
  "smartadserver.com",
  "media.net",
  "moatads.com",
  "doubleverify.com",
  "adsafeprotected.com",
  "serving-sys.com",
  "2mdn.net",
  "exoclick.com",
  "exosrv.com",
  "juicyads.com",
  "mgid.com",
  "revcontent.com",
  "adcash.com",
  "propellerads.com",
  "adsterra.com",
  "facebook.com/tr",
  "static.ads-twitter.com",
  "ads.linkedin.com",
  "yieldmo.com",
  "lijit.com",
  "sharethrough.com",
  "triplelift.com",
  "teads.tv",
  "spotxchange.com",
  "spotx.tv",
  "springserve.com",
  "contextweb.com",
  "imrworldwide.com",
  "mfadsrvr.com",
  "admanmedia.com",
  "/ads.",
  "/ad.",
  "/advert",
  "/banner",
  "/popup",
  "/interstitial",
  "/pagead/",
  "/pubads",
  "/prebid",
];

const TRACKER_PATTERNS = [
  "google-analytics.com",
  "googleanalytics.com",
  "analytics.google.com",
  "googletagmanager.com",
  "gtag/js",
  "quantserve.com",
  "quantcount.com",
  "scorecardresearch.com",
  "hotjar.com",
  "hotjar.io",
  "mixpanel.com",
  "cdn.mxpnl.com",
  "optimizely.com",
  "segment.io",
  "segment.com",
  "cdn.segment.com",
  "kissmetrics.com",
  "crazyegg.com",
  "flurry.com",
  "fullstory.com",
  "mouseflow.com",
  "amplitude.com",
  "heap.io",
  "heapanalytics.com",
  "chartbeat.com",
  "chartbeat.net",
  "comscore.com",
  "adobedtm.com",
  "demdex.net",
  "bluekai.com",
  "tapad.com",
  "mathtag.com",
  "lotame.com",
  "krxd.net",
  "branch.io",
  "appsflyer.com",
  "adjust.com",
  "connect.facebook.net",
  "pixel.facebook.com",
  "fbevents.js",
  "bat.bing.com",
  "clarity.ms",
  "omtrdc.net",
  "2o7.net",
  "everesttech.net",
  "rlcdn.com",
  "agkn.com",
  "turn.com",
  "simpli.fi",
  "sitescout.com",
  "bidr.io",
  "crwdcntrl.net",
  "eyeota.net",
  "/analytics",
  "/tracking",
  "/tracker",
  "/beacon",
  "/collect?",
  "/ga.js",
];

let adBlockDebug = false;
let dnrDebugActive = false;
const _countedRequestIds = new Set();
const COUNTED_REQUEST_TTL = 60000;

function adLog() {
  if (adBlockDebug) console.log("[WebShield AdBlock]", ...arguments);
}

function classifyUrl(urlStr) {
  const isAd = AD_PATTERNS.some((p) => urlStr.includes(p));
  const isTracker = !isAd && TRACKER_PATTERNS.some((p) => urlStr.includes(p));
  return { isAd, isTracker };
}

function markRequestCounted(requestId) {
  if (requestId === undefined) return false;
  if (_countedRequestIds.has(requestId)) return true;
  _countedRequestIds.add(requestId);
  setTimeout(() => _countedRequestIds.delete(requestId), COUNTED_REQUEST_TTL);
  return false;
}

// Initialize ruleset on startup
chrome.storage.local.get({ adBlockEnabled: true, adBlockDebug: false }, (res) => {
  adBlockDebug = !!res.adBlockDebug;
  if (res.adBlockEnabled) {
    enableAdBlocker().then(() => logDnrStatus());
  } else {
    disableAdBlocker();
  }
});

chrome.storage.onChanged.addListener((changes, area) => {
  if (area === "local") {
    if (changes.adBlockEnabled) {
      if (changes.adBlockEnabled.newValue) {
        enableAdBlocker().then(() => logDnrStatus());
      } else {
        disableAdBlocker();
      }
    }
    if (changes.adBlockDebug) {
      adBlockDebug = !!changes.adBlockDebug.newValue;
    }
  }
});

async function logDnrStatus() {
  try {
    const enabled = await chrome.declarativeNetRequest.getEnabledRulesets();
    adLog("DNR enabled rulesets:", enabled);
    if (chrome.declarativeNetRequest.getAvailableStaticRuleCount) {
      const available = await chrome.declarativeNetRequest.getAvailableStaticRuleCount();
      adLog("DNR available static rule slots:", available);
    }
  } catch (err) {
    adLog("DNR diagnostics error:", err.message);
  }
}

// Chained promise queue to prevent race conditions during async storage write operations
let updateQueue = Promise.resolve();

function incrementCounters(tabId, isAd, isTracker, source, url) {
  updateQueue = updateQueue
    .then(async () => {
      const sessionKey = `tab_stats_${tabId}`;

      let sessionData = await chrome.storage.session.get(sessionKey);
      let tabStats = sessionData[sessionKey] || { ads: 0, trackers: 0 };
      if (isAd) tabStats.ads++;
      if (isTracker) tabStats.trackers++;
      await chrome.storage.session.set({ [sessionKey]: tabStats });

      let localData = await chrome.storage.local.get({
        totalAds: 0,
        totalTrackers: 0,
      });
      let totalAds = localData.totalAds || 0;
      let totalTrackers = localData.totalTrackers || 0;
      if (isAd) totalAds++;
      if (isTracker) totalTrackers++;
      await chrome.storage.local.set({ totalAds, totalTrackers });

      adLog(
        "Blocked",
        isAd ? "ad" : "tracker",
        `via ${source}`,
        url ? url.slice(0, 120) : "",
        `tab ${tabId}: ${tabStats.ads}a/${tabStats.trackers}t`,
      );
    })
    .catch((err) => console.error("[WebShield] Error updating stats storage:", err));
}

// Fallback counter: webRequest when DNR debug listener is unavailable
chrome.webRequest.onBeforeRequest.addListener(
  (details) => {
    if (dnrDebugActive) return;
    if (details.url.startsWith("chrome-extension://")) return;

    chrome.storage.local.get({ adBlockEnabled: true }, (res) => {
      if (!res.adBlockEnabled) return;

      const urlStr = details.url.toLowerCase();
      const tabId = details.tabId;
      if (tabId < 0) return;

      if (markRequestCounted(details.requestId)) return;

      const { isAd, isTracker } = classifyUrl(urlStr);
      if (isAd || isTracker) {
        incrementCounters(tabId, isAd, isTracker, "webRequest", urlStr);
        refreshBadgeCount(tabId);
      }
    });
  },
  { urls: ["<all_urls>"] },
);

// Reset tab-specific stats when a navigation starts on the main frame
chrome.webNavigation.onBeforeNavigate.addListener((details) => {
  if (details.frameId !== 0) return;
  const tabId = details.tabId;
  chrome.storage.session.remove(`tab_stats_${tabId}`).catch(() => {});
});

// DNR rule-match tracking (exact counts in developer/unpacked mode)
if (
  chrome.declarativeNetRequest &&
  chrome.declarativeNetRequest.onRuleMatchedDebug &&
  typeof chrome.declarativeNetRequest.onRuleMatchedDebug.addListener === "function"
) {
  dnrDebugActive = true;
  chrome.declarativeNetRequest.onRuleMatchedDebug.addListener((info) => {
    const tabId = info.request && info.request.tabId;
    if (tabId === undefined || tabId < 0) return;

    const requestId = info.request.requestId;
    if (markRequestCounted(requestId)) return;

    const urlStr = (info.request.url || "").toLowerCase();
    const { isAd, isTracker } = classifyUrl(urlStr);
    incrementCounters(tabId, isAd || !isTracker, isTracker, "DNR", urlStr);
    refreshBadgeCount(tabId);
  });
  adLog("DNR onRuleMatchedDebug listener active");
}

// Cosmetic filtering + diagnostics message handler
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (!message || !message.action) return false;

  if (message.action === "cosmeticHide") {
    const tabId = sender.tab && sender.tab.id;
    if (tabId !== undefined && tabId >= 0) {
      chrome.storage.local.get({ adBlockEnabled: true }, (res) => {
        if (!res.adBlockEnabled) return;
        incrementCounters(tabId, true, false, "cosmetic", message.tag || "");
        refreshBadgeCount(tabId);
      });
    }
    sendResponse({ ok: true });
    return true;
  }

  if (message.action === "getDnrDiagnostics") {
    getDnrDiagnostics().then(sendResponse);
    return true;
  }

  if (message.action === "setAdBlockDebug") {
    setAdBlockDebug(message.enabled).then(() => {
      adBlockDebug = !!message.enabled;
      sendResponse({ ok: true });
    });
    return true;
  }

  return false;
});

// ── Badge: show blocked-ad count for the active tab ───────────────────────────
async function refreshBadgeCount(tabId) {
  try {
    const sessionKey = `tab_stats_${tabId}`;
    const sessionData = await chrome.storage.session.get(sessionKey);
    const stats = sessionData[sessionKey] || { ads: 0, trackers: 0 };
    const blocked = (stats.ads || 0) + (stats.trackers || 0);

    const scanData = await chrome.storage.session.get(`scan_${tabId}`);
    const cached = scanData[`scan_${tabId}`];
    if (cached && (cached.verdict === "PHISHING" || cached.verdict === "SUSPICIOUS")) {
      return;
    }

    chrome.storage.local.get({ adBlockEnabled: true }, (res) => {
      if (!res.adBlockEnabled) return;
      if (blocked > 0) {
        chrome.action.setBadgeText({
          text: blocked > 999 ? "999+" : String(blocked),
          tabId,
        });
        chrome.action.setBadgeBackgroundColor({ color: "#22c55e", tabId });
      }
    });
  } catch {
    // tab may have closed
  }
}
