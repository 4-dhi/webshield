// WebShield.AI — Content Script Orchestrator
// Coordinates page-level security: redirect traps, credential harvesting, fake login detection.

(function () {
  "use strict";

  if (window.__webshieldContent) return;
  window.__webshieldContent = true;

  const PHISHING_FORM_PATTERNS = [
    /password/i, /passwd/i, /login/i, /sign.?in/i, /credential/i,
    /ssn/i, /social.?security/i, /card.?number/i, /cvv/i, /pin/i,
  ];

  const FAKE_LOGIN_HOST_RE =
    /paypal|apple|microsoft|google|amazon|netflix|instagram|facebook|twitter|linkedin|bank|wallet|metamask/i;

  let enabled = true;
  let navigationGuard = true;
  const originalOpen = window.open;

  try {
    chrome.storage.local.get({ adBlockEnabled: true }, (res) => {
      enabled = res.adBlockEnabled !== false;
    });
  } catch { /* no storage */ }

  // ── Popup / popunder / tab-under prevention ────────────────────────────────
  window.open = function (url, target, features) {
    if (!enabled) return originalOpen.apply(this, arguments);
    const urlStr = String(url || "");
    if (/popunder|popup|ads?|click|redirect|track/i.test(urlStr)) {
      try {
        chrome.runtime.sendMessage({ action: "blockPopup", url: urlStr });
      } catch { /* ignore */ }
      return null;
    }
    if (target === "_blank" && /ad|track|click|redirect/i.test(urlStr)) return null;
    return originalOpen.apply(this, arguments);
  };

  // Block beforeunload redirect traps
  window.addEventListener("beforeunload", (e) => {
    if (!enabled) return;
    // Don't prevent normal navigation, only log suspicious patterns
  }, true);

  // ── Malicious redirect detection ───────────────────────────────────────────
  const REDIRECT_PATTERNS = [
    /doubleclick/i, /popads/i, /propellerads/i, /adsterra/i,
    /click\./i, /trk\./i, /redirect/i, /go2cloud/i,
  ];

  function isMaliciousRedirect(url) {
    return REDIRECT_PATTERNS.some((re) => re.test(url));
  }

  // Intercept meta refresh redirects to ad domains
  function scanMetaRefresh() {
    document.querySelectorAll('meta[http-equiv="refresh" i]').forEach((meta) => {
      const content = (meta.getAttribute("content") || "").toLowerCase();
      if (REDIRECT_PATTERNS.some((re) => re.test(content))) {
        meta.remove();
        try {
          chrome.runtime.sendMessage({ action: "blockRedirect", type: "meta-refresh" });
        } catch { /* ignore */ }
      }
    });
  }

  // ── Credential harvesting detection ────────────────────────────────────────
  function scanCredentialForms() {
    const host = location.hostname.toLowerCase();
    const isTrustedBrandOnWrongHost =
      FAKE_LOGIN_HOST_RE.test(host) &&
      !host.endsWith(".google.com") &&
      !host.endsWith(".apple.com") &&
      !host.endsWith(".microsoft.com") &&
      !host.endsWith(".amazon.com") &&
      !host.endsWith(".paypal.com") &&
      !host.endsWith(".facebook.com") &&
      !host.endsWith(".twitter.com") &&
      !host.endsWith(".x.com") &&
      !host.endsWith(".instagram.com") &&
      !host.endsWith(".linkedin.com") &&
      !host.endsWith(".netflix.com");

    document.querySelectorAll("form").forEach((form) => {
      const inputs = form.querySelectorAll("input[type='password'], input[name*='pass' i], input[name*='card' i]");
      if (inputs.length === 0) return;

      const action = (form.action || location.href).toLowerCase();
      const suspiciousAction = /bit\.ly|tinyurl|t\.co|goo\.gl|is\.gd/i.test(action);

      if (isTrustedBrandOnWrongHost || suspiciousAction) {
        form.style.outline = "3px solid #dc2626";
        form.dataset.webshieldSuspicious = "1";
        try {
          chrome.runtime.sendMessage({
            action: "suspiciousForm",
            host: host,
            action: action,
          });
        } catch { /* ignore */ }
      }
    });
  }

  // ── Fake notification prompt removal ───────────────────────────────────────
  function removeFakeNotifications() {
    document.querySelectorAll(
      "[class*='notification-permission'], [class*='push-prompt'], [id*='push-prompt']",
    ).forEach((el) => {
      const text = (el.innerText || "").toLowerCase();
      if (/allow notifications|enable notifications|click allow/i.test(text)) {
        el.remove();
      }
    });
  }

  // ── Page load timing for analytics ─────────────────────────────────────────
  const loadStart = performance.now();
  window.addEventListener("load", () => {
    const loadMs = Math.round(performance.now() - loadStart);
    try {
      chrome.runtime.sendMessage({ action: "pageLoadTime", ms: loadMs });
    } catch { /* ignore */ }
  });

  // ── HTML extraction for popup (legacy API) ─────────────────────────────────
  chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    if (request.action === "getPageHTML") {
      try {
        sendResponse({ success: true, html: document.documentElement.outerHTML });
      } catch (error) {
        sendResponse({ success: false, error: error.message });
      }
    }
    return true;
  });

  // ── Periodic security scan ─────────────────────────────────────────────────
  function securityScan() {
    if (!enabled) return;
    scanMetaRefresh();
    scanCredentialForms();
    removeFakeNotifications();
  }

  const observer = new MutationObserver(() => securityScan());
  if (document.documentElement) {
    observer.observe(document.documentElement, { childList: true, subtree: true });
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", securityScan, { once: true });
  } else {
    securityScan();
  }
})();
