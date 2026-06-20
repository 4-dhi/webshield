// WebShield.AI — Analytics & Statistics Engine
// Tracks blocked ads, trackers, malware, phishing, privacy score, and page metrics.

const WS_STATS_DEFAULTS = {
  totalAds: 0,
  totalTrackers: 0,
  totalMalware: 0,
  totalPhishing: 0,
  totalFingerprint: 0,
  totalMiners: 0,
  totalCosmetic: 0,
  totalAntiAdblock: 0,
  privacyScore: 100,
  pageLoadSavedMs: 0,
};

let wsStatsQueue = Promise.resolve();
const wsCountedRequestIds = new Set();
const WS_COUNTED_TTL = 60000;

function wsMarkRequestCounted(requestId) {
  if (requestId === undefined) return false;
  if (wsCountedRequestIds.has(requestId)) return true;
  wsCountedRequestIds.add(requestId);
  setTimeout(() => wsCountedRequestIds.delete(requestId), WS_COUNTED_TTL);
  return false;
}

function wsIncrementStats(tabId, event) {
  wsStatsQueue = wsStatsQueue
    .then(async () => {
      const sessionKey = `tab_stats_${tabId}`;
      const sessionData = await chrome.storage.session.get(sessionKey);
      const tabStats = sessionData[sessionKey] || {
        ads: 0, trackers: 0, malware: 0, phishing: 0,
        fingerprint: 0, miners: 0, cosmetic: 0, antiAdblock: 0,
      };

      const localData = await chrome.storage.local.get(WS_STATS_DEFAULTS);
      const totals = { ...WS_STATS_DEFAULTS, ...localData };

      const map = {
        ad: ["ads", "totalAds"],
        tracker: ["trackers", "totalTrackers"],
        malware: ["malware", "totalMalware"],
        phishing: ["phishing", "totalPhishing"],
        fingerprint: ["fingerprint", "totalFingerprint"],
        miner: ["miners", "totalMiners"],
        cosmetic: ["cosmetic", "totalCosmetic"],
        antiAdblock: ["antiAdblock", "totalAntiAdblock"],
      };

      const keys = map[event.type];
      if (keys) {
        tabStats[keys[0]] = (tabStats[keys[0]] || 0) + 1;
        totals[keys[1]] = (totals[keys[1]] || 0) + 1;
      }

      // Privacy score: each block slightly improves score up to 100
      const blocked = totals.totalAds + totals.totalTrackers + totals.totalFingerprint;
      totals.privacyScore = Math.min(100, 50 + Math.floor(Math.log10(blocked + 1) * 25));

      await chrome.storage.session.set({ [sessionKey]: tabStats });
      await chrome.storage.local.set(totals);
    })
    .catch((err) => console.error("[WebShield Stats]", err));
}

async function wsGetStats(tabId) {
  const localData = await chrome.storage.local.get(WS_STATS_DEFAULTS);
  if (!tabId) {
    return {
      page: { ads: 0, trackers: 0, malware: 0, phishing: 0 },
      totals: localData,
      privacyScore: localData.privacyScore || 100,
    };
  }
  const sessionData = await chrome.storage.session.get(`tab_stats_${tabId}`);
  const tabStats = sessionData[`tab_stats_${tabId}`] || {};
  return {
    page: {
      ads: tabStats.ads || 0,
      trackers: tabStats.trackers || 0,
      malware: tabStats.malware || 0,
      phishing: tabStats.phishing || 0,
      fingerprint: tabStats.fingerprint || 0,
      miners: tabStats.miners || 0,
      cosmetic: tabStats.cosmetic || 0,
      antiAdblock: tabStats.antiAdblock || 0,
    },
    totals: localData,
    privacyScore: localData.privacyScore || 100,
  };
}

async function wsResetStats(tabId) {
  await chrome.storage.local.set(WS_STATS_DEFAULTS);
  if (tabId) {
    await chrome.storage.session.remove(`tab_stats_${tabId}`);
  } else {
    const sessionData = await chrome.storage.session.get(null);
    const keys = Object.keys(sessionData).filter((k) => k.startsWith("tab_stats_"));
    if (keys.length) await chrome.storage.session.remove(keys);
  }
}

async function wsRefreshBadge(tabId) {
  try {
    const stats = await wsGetStats(tabId);
    const blocked =
      (stats.page.ads || 0) + (stats.page.trackers || 0) +
      (stats.page.malware || 0) + (stats.page.cosmetic || 0);

    const scanData = await chrome.storage.session.get(`scan_${tabId}`);
    const cached = scanData[`scan_${tabId}`];
    if (cached && (cached.verdict === "PHISHING" || cached.verdict === "SUSPICIOUS")) return;

    const { adBlockEnabled = true } = await chrome.storage.local.get({ adBlockEnabled: true });
    if (!adBlockEnabled) return;

    if (blocked > 0) {
      chrome.action.setBadgeText({
        text: blocked > 999 ? "999+" : String(blocked),
        tabId,
      });
      chrome.action.setBadgeBackgroundColor({ color: "#22c55e", tabId });
    }
  } catch {
    // tab closed
  }
}

function wsRecordBlock(tabId, classification, source, requestId) {
  if (wsMarkRequestCounted(requestId)) return;

  let type = "ad";
  if (classification.isTracker) type = "tracker";
  if (classification.category === "malware") type = "malware";
  if (classification.category === "miner") type = "miner";
  if (classification.category === "fingerprint") type = "fingerprint";
  if (classification.isAd && !classification.isTracker) type = "ad";

  wsIncrementStats(tabId, { type, source });
  wsRefreshBadge(tabId);
}

// Legacy compatibility wrappers
function markRequestCounted(requestId) { return wsMarkRequestCounted(requestId); }
function incrementCounters(tabId, isAd, isTracker, source, url) {
  wsRecordBlock(tabId, { isAd, isTracker, category: isAd ? "ad" : "tracker" }, source);
}
function refreshBadgeCount(tabId) { wsRefreshBadge(tabId); }
