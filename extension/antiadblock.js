// WebShield.AI — Anti-Adblock Countermeasures Engine
// Detects and removes adblock warnings, paywalls, disable-adblock popups, overlay blockers.

(function () {
  "use strict";

  if (window.__webshieldAntiAdblock) return;
  window.__webshieldAntiAdblock = true;

  let enabled = true;
  let observer = null;
  let debounceTimer = null;

  const WARNING_SELECTORS = [
    // Generic anti-adblock
    "#adb-enabled", "#adblocker-notify", "#adblock-notify",
    ".adblocker-notify", ".adblock-notice", ".adblock-warning",
    ".adblock-detected", ".ad-blocker-detected", ".adblock-popup",
    "#adblock-popup", "#adblock-modal", "#adblock-overlay",
    "[class*='adblock-detected']", "[id*='adblock-detected']",
    "[class*='adblocker-detected']", "[id*='adblocker-detected']",
    "[class*='anti-adblock']", "[id*='anti-adblock']",
    "[class*='adblock-message']", "[id*='adblock-message']",
    // Paywall overlays
    ".tp-modal", ".tp-backdrop", ".piano-modal", ".paywall-overlay",
    ".gateway-content", ".meter-modal", ".regwall-modal",
    "[class*='paywall']", "[id*='paywall']",
    "[class*='subscription-wall']", "[id*='subscription-wall']",
    // Disable-adblock prompts
    ".fc-consent-root", ".qc-cmp2-container",
    "#sp_message_container", "#onetrust-banner-sdk",
    ".snigel-adconsent", ".adconsent",
    // Fake notification prompts
    "[class*='push-notification-prompt']",
    "[class*='fake-notification']",
    "[id*='push-notif']",
    ".webpush-notification-prompt",
    // Overlay blockers
    ".fc-ab-root", "#fancybox-overlay",
    ".blockOverlay", ".modal-backdrop.show",
  ];

  const WARNING_TEXT_RE =
    /adblock|ad blocker|ad-blocker|disable your ad|whitelist us|allow ads|support us by disabling|please disable|turn off your ad/i;

  const CSS_RULE = WARNING_SELECTORS.map(
    (s) => `${s}{display:none!important;visibility:hidden!important;pointer-events:none!important}`,
  ).join("");

  try {
    chrome.storage.local.get({ adBlockEnabled: true }, (res) => {
      if (res.adBlockEnabled === false) teardown();
    });
    chrome.storage.onChanged.addListener((changes, area) => {
      if (area === "local" && changes.adBlockEnabled) {
        enabled = changes.adBlockEnabled.newValue !== false;
        if (!enabled) teardown();
        else boot();
      }
    });
  } catch { /* no storage */ }

  function reportRemoval(tag) {
    try {
      chrome.runtime.sendMessage({ action: "antiAdblockRemoved", tag: tag || "antiadblock" });
    } catch { /* context invalidated */ }
  }

  function injectCSS() {
    if (document.getElementById("webshield-antiadblock-css")) return;
    const style = document.createElement("style");
    style.id = "webshield-antiadblock-css";
    style.textContent = CSS_RULE;
    (document.documentElement || document.head).appendChild(style);
  }

  function restoreScroll() {
    [document.documentElement, document.body].forEach((el) => {
      if (!el) return;
      el.style.setProperty("overflow", "auto", "important");
      el.style.setProperty("position", "static", "important");
      el.classList.remove("no-scroll", "modal-open", "overflow-hidden", "noscroll", "adblock-detected");
    });
  }

  function hideElement(el) {
    if (!el || el.dataset.webshieldAntiAdblock) return;
    if (el.id === "webshield-warning") return;
    el.style.setProperty("display", "none", "important");
    el.style.setProperty("visibility", "hidden", "important");
    el.style.setProperty("pointer-events", "none", "important");
    el.dataset.webshieldAntiAdblock = "1";
    reportRemoval(el.tagName);
    restoreScroll();
  }

  function scanBySelector() {
    const sel = WARNING_SELECTORS.join(",");
    try {
      document.querySelectorAll(sel).forEach(hideElement);
    } catch { /* invalid selector in old browsers */ }
  }

  function scanByText() {
    const candidates = document.querySelectorAll(
      "div, section, aside, dialog, [role='dialog'], [role='alertdialog']",
    );
    for (let i = 0; i < candidates.length; i++) {
      const el = candidates[i];
      if (el.dataset && el.dataset.webshieldAntiAdblock) continue;
      const text = (el.innerText || "").slice(0, 500);
      if (text.length < 10) continue;
      if (WARNING_TEXT_RE.test(text)) {
        let style;
        try { style = getComputedStyle(el); } catch { continue; }
        const z = parseInt(style.zIndex, 10);
        const pos = style.position;
        if (z > 100 || pos === "fixed" || pos === "absolute" || text.length < 300) {
          hideElement(el);
        }
      }
    }
  }

  function neutralizeDetectionScripts() {
    // Stub common adblock detection globals
    const stubs = {
      canRunAds: true,
      isAdBlockActive: false,
      adblock: false,
      adBlockEnabled: false,
      google_ad_status: 1,
    };
    for (const [key, val] of Object.entries(stubs)) {
      try {
        Object.defineProperty(window, key, { get: () => val, configurable: true });
      } catch { window[key] = val; }
    }

    // Intercept bait element checks
    const origQS = document.querySelector.bind(document);
    document.querySelector = function (sel) {
      if (typeof sel === "string" && /adsbox|ad-placement|ad_container|ad-banner/i.test(sel)) {
        return null;
      }
      return origQS(sel);
    };
  }

  function runScan() {
    if (!enabled) return;
    injectCSS();
    scanBySelector();
    scanByText();
    restoreScroll();
  }

  function scheduleScan() {
    if (debounceTimer) clearTimeout(debounceTimer);
    debounceTimer = setTimeout(runScan, 80);
  }

  function boot() {
    if (observer) return;
    neutralizeDetectionScripts();
    injectCSS();
    runScan();

    observer = new MutationObserver(scheduleScan);
    const target = document.documentElement || document.body;
    if (target) {
      observer.observe(target, {
        childList: true, subtree: true, attributes: true,
        attributeFilter: ["class", "id", "style"],
      });
    }

    window.addEventListener("popstate", scheduleScan);
    window.addEventListener("hashchange", scheduleScan);
  }

  function teardown() {
    if (observer) { observer.disconnect(); observer = null; }
    if (debounceTimer) { clearTimeout(debounceTimer); debounceTimer = null; }
  }

  boot();
})();
