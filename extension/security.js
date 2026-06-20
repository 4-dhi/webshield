// WebShield.AI — Security Engine (background)
// Malware/phishing domain blocking, redirect prevention, scam detection.

const WS_SCAM_TLDS = [
  ".xyz", ".top", ".click", ".link", ".gq", ".ml", ".tk", ".cf", ".ga",
  ".buzz", ".monster", ".rest", ".sbs", ".cfd",
];

const WS_PHISHING_KEYWORDS = [
  "login-verify", "account-secure", "password-reset", "signin-confirm",
  "banking-secure", "wallet-connect", "metamask", "crypto-claim",
  "paypal-secure", "apple-id-verify", "microsoft-login", "google-verify",
  "amazon-refund", "netflix-billing", "instagram-verify",
];

const WS_MALWARE_DOMAINS = new Set([
  "malware.testcategory.com",
]);

const WS_REDIRECT_BLOCK_PATTERNS = [
  "doubleclick.net", "popads.net", "popcash.net", "propellerads.com",
  "adsterra.com", "exoclick.com", "onclickads.net", "clksite.com",
  "redirectvoluum.com", "go2cloud.org", "trk.", "click.", "track.",
];

function wsIsScamDomain(hostname) {
  if (!hostname) return false;
  const lower = hostname.toLowerCase();
  if (WS_SCAM_TLDS.some((tld) => lower.endsWith(tld))) {
    if (WS_PHISHING_KEYWORDS.some((kw) => lower.includes(kw))) return true;
  }
  if (WS_PHISHING_KEYWORDS.some((kw) => lower.includes(kw))) return true;
  return false;
}

function wsIsMalwareUrl(urlStr) {
  const lower = (urlStr || "").toLowerCase();
  try {
    const host = new URL(lower).hostname;
    if (WS_MALWARE_DOMAINS.has(host)) return true;
  } catch { /* ignore */ }
  return /malware|virus|trojan|ransomware|exploit/i.test(lower);
}

function wsIsRedirectAd(urlStr) {
  return WS_REDIRECT_BLOCK_PATTERNS.some((p) => (urlStr || "").toLowerCase().includes(p));
}

function wsEvaluateNavigation(url, referrer) {
  const result = { block: false, reason: null, category: null };
  if (!url || !url.startsWith("http")) return result;

  let hostname = "";
  try { hostname = new URL(url).hostname; } catch { return result; }

  if (wsIsMalwareUrl(url)) {
    return { block: true, reason: "Known malware domain", category: "malware" };
  }
  if (wsIsScamDomain(hostname)) {
    return { block: true, reason: "Suspected phishing/scam domain", category: "phishing" };
  }
  if (wsIsRedirectAd(url) && referrer) {
    return { block: true, reason: "Blocked redirect ad", category: "redirect" };
  }
  return result;
}

async function wsBlockMalwareDomain(domain, tabId) {
  const filter = `||${domain}^`;
  const ruleId = await wsAddDynamicRule(filter, { priority: 30 });
  if (tabId && ruleId) {
    wsRecordBlock(tabId, { category: "malware", isAd: false, isTracker: false }, "security");
  }
  return ruleId;
}

// Listen for navigation threats
function wsInitSecurityListeners() {
  chrome.webNavigation.onBeforeNavigate.addListener((details) => {
    if (details.frameId !== 0) return;
    const eval_ = wsEvaluateNavigation(details.url, details.transitionQualifiers);
    if (eval_.block) {
      wsIncrementStats(details.tabId, { type: eval_.category === "malware" ? "malware" : "phishing" });
    }
  });
}
