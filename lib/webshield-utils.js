/**
 * WebShield.AI — Shared testable utilities
 * Used by unit tests and mirrored in extension/tracker.js
 */

const AD_PATTERNS = [
  "doubleclick.net", "googlesyndication.com", "pagead/", "youtube.com/api/stats/ads",
];
const TRACKER_PATTERNS = ["google-analytics.com", "googletagmanager.com", "/collect?"];
const MINER_PATTERNS = ["coinhive.com", "crypto-loot.com"];
const FINGERPRINT_PATTERNS = ["fingerprintjs.com", "fpjs.io"];

function extractHostname(urlStr) {
  try { return new URL(urlStr).hostname.toLowerCase(); } catch { return ""; }
}

function isThirdParty(requestUrl, pageUrl) {
  if (!pageUrl) return true;
  const reqHost = extractHostname(requestUrl);
  const pageHost = extractHostname(pageUrl);
  if (!reqHost || !pageHost) return true;
  if (reqHost === pageHost) return false;
  if (reqHost.endsWith("." + pageHost) || pageHost.endsWith("." + reqHost)) return false;
  return true;
}

function matchesPatterns(urlStr, patterns) {
  const lower = (urlStr || "").toLowerCase();
  return patterns.some((p) => lower.includes(p));
}

function classifyRequest(urlStr, pageUrl) {
  const lower = (urlStr || "").toLowerCase();
  const thirdParty = isThirdParty(lower, pageUrl);
  if (matchesPatterns(lower, MINER_PATTERNS))
    return { category: "miner", isAd: true, isTracker: false, thirdParty };
  if (matchesPatterns(lower, FINGERPRINT_PATTERNS))
    return { category: "fingerprint", isAd: false, isTracker: true, thirdParty };
  if (matchesPatterns(lower, AD_PATTERNS))
    return { category: "ad", isAd: true, isTracker: false, thirdParty };
  if (matchesPatterns(lower, TRACKER_PATTERNS))
    return { category: "tracker", isAd: false, isTracker: true, thirdParty };
  return { category: "unknown", isAd: false, isTracker: false, thirdParty };
}

function isScamDomain(hostname) {
  const lower = (hostname || "").toLowerCase();
  const scamTlds = [".xyz", ".top", ".click"];
  const keywords = ["login-verify", "password-reset", "wallet-connect"];
  if (scamTlds.some((t) => lower.endsWith(t)) && keywords.some((k) => lower.includes(k))) return true;
  return keywords.some((k) => lower.includes(k));
}

function optimizeRules(rules) {
  const seen = new Map();
  const toRemove = new Set();
  for (const rule of rules) {
    const key = rule.filter || rule.urlFilter || "";
    const prev = seen.get(key);
    if (prev) {
      if (rule.priority < prev.priority) toRemove.add(rule.id);
      else { toRemove.add(prev.id); seen.set(key, rule); }
    } else seen.set(key, rule);
  }
  return rules.filter((r) => !toRemove.has(r.id));
}

module.exports = {
  classifyRequest, isThirdParty, isScamDomain, optimizeRules, extractHostname,
};
