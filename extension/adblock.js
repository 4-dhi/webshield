// WebShield.AI — Core Ad Blocker API Module
// Exposes reusable settings and rule management functions for both background and popup contexts.

function enableAdBlocker() {
  return chrome.storage.local
    .set({ adBlockEnabled: true })
    .then(() => {
      return chrome.declarativeNetRequest.updateEnabledRulesets({
        enableRulesetIds: ["ruleset_1"],
      });
    })
    .catch((err) => console.error("Error enabling ad blocker:", err));
}

function disableAdBlocker() {
  return chrome.storage.local
    .set({ adBlockEnabled: false })
    .then(() => {
      return chrome.declarativeNetRequest.updateEnabledRulesets({
        disableRulesetIds: ["ruleset_1"],
      });
    })
    .catch((err) => console.error("Error disabling ad blocker:", err));
}

function getBlockedAdsCount(tabId, callback) {
  if (typeof tabId === "function") {
    callback = tabId;
    tabId = null;
  }
  const promise = new Promise((resolve) => {
    chrome.storage.local.get({ totalAds: 0, totalTrackers: 0 }, (localData) => {
      if (tabId) {
        chrome.storage.session.get(`tab_stats_${tabId}`, (sessionData) => {
          const tabStats = sessionData[`tab_stats_${tabId}`] || {
            ads: 0,
            trackers: 0,
          };
          resolve({
            pageAds: tabStats.ads || 0,
            pageTrackers: tabStats.trackers || 0,
            totalAds: localData.totalAds || 0,
            totalTrackers: localData.totalTrackers || 0,
          });
        });
      } else {
        resolve({
          pageAds: 0,
          pageTrackers: 0,
          totalAds: localData.totalAds || 0,
          totalTrackers: localData.totalTrackers || 0,
        });
      }
    });
  });

  if (callback) {
    promise.then(callback);
  }
  return promise;
}
function resetBlockedAdsCount(tabId, callback) {
  if (typeof tabId === "function") {
    callback = tabId;
    tabId = null;
  }
  const promise = new Promise(async (resolve) => {
    await chrome.storage.local.set({ totalAds: 0, totalTrackers: 0 });

    if (tabId) {
      await chrome.storage.session.remove(`tab_stats_${tabId}`);
    } else {
      // If tabId not specified, clean up all session tab stats
      const sessionData = await chrome.storage.session.get(null);
      const keysToRemove = Object.keys(sessionData).filter((key) =>
        key.startsWith("tab_stats_"),
      );
      if (keysToRemove.length > 0) {
        await chrome.storage.session.remove(keysToRemove);
      }
    }
    resolve();
  });
  if (callback) {
    promise.then(callback);
  }
  return promise;
}
