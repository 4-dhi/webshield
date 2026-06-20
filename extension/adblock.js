// WebShield.AI — Core Ad Blocker API Module
// Settings, rule management, and integration with rules-engine + stats.

function enableAdBlocker() {
  return chrome.storage.local
    .set({ adBlockEnabled: true })
    .then(() => wsEnableAllRulesets())
    .then(() => wsInstallDynamicRules())
    .catch((err) => console.error("[WebShield] Error enabling ad blocker:", err));
}

function disableAdBlocker() {
  return chrome.storage.local
    .set({ adBlockEnabled: false })
    .then(() => wsDisableAllRulesets())
    .catch((err) => console.error("[WebShield] Error disabling ad blocker:", err));
}

function getBlockedAdsCount(tabId, callback) {
  if (typeof tabId === "function") {
    callback = tabId;
    tabId = null;
  }
  const promise = wsGetStats(tabId).then((stats) => ({
    pageAds: stats.page.ads || 0,
    pageTrackers: stats.page.trackers || 0,
    totalAds: stats.totals.totalAds || 0,
    totalTrackers: stats.totals.totalTrackers || 0,
    totalMalware: stats.totals.totalMalware || 0,
    totalPhishing: stats.totals.totalPhishing || 0,
    privacyScore: stats.privacyScore || 100,
  }));

  if (callback) promise.then(callback);
  return promise;
}

function resetBlockedAdsCount(tabId, callback) {
  if (typeof tabId === "function") {
    callback = tabId;
    tabId = null;
  }
  const promise = wsResetStats(tabId);
  if (callback) promise.then(callback);
  return promise;
}

function getDnrDiagnostics() {
  return wsGetRulesDiagnostics();
}

function setAdBlockDebug(enabled) {
  return chrome.storage.local.set({ adBlockDebug: !!enabled });
}

async function optimizeRules() {
  return wsOptimizeRules();
}
