// WebShield.AI — Cosmetic Filtering Engine
// Hides ad/banner/sponsor elements, full-page interstitials, anchor ads and
// pop-overlays, and re-scans the DOM for elements injected after initial
// page load (lazy-loaded ads, SPA content, timed interstitials, etc).

(function () {
  "use strict";

  if (window.__webshieldCosmetic) return;
  window.__webshieldCosmetic = true;

  let debugEnabled = false;
  let enabled = true;
  let observer = null;
  let periodicTimer = null;
  let debounceTimer = null;
  let hideCount = 0;
  let pendingScan = false;

  try {
    chrome.storage.local.get({ adBlockDebug: false, adBlockEnabled: true }, (res) => {
      debugEnabled = !!res.adBlockDebug;
      if (res.adBlockEnabled === false) teardown();
    });
    chrome.storage.onChanged.addListener((changes, area) => {
      if (area !== "local") return;
      if (changes.adBlockDebug) debugEnabled = !!changes.adBlockDebug.newValue;
      if (changes.adBlockEnabled) {
        enabled = changes.adBlockEnabled.newValue !== false;
        if (!enabled) teardown();
        else if (!observer) boot();
      }
    });
  } catch {
    // storage unavailable
  }

  boot();

  function log() {
    if (debugEnabled) console.log("[WebShield Cosmetic]", ...arguments);
  }

  function teardown() {
    if (observer) { observer.disconnect(); observer = null; }
    if (periodicTimer) { clearInterval(periodicTimer); periodicTimer = null; }
    if (debounceTimer) { clearTimeout(debounceTimer); debounceTimer = null; }
  }

  // ── 1. Specific high-confidence ad/interstitial selectors ──────────────────
  const SPECIFIC_SELECTORS = [
    '[id*="google_ads"]',
    '[id^="div-gpt-ad"]',
    '[id*="adsbygoogle"]',
    'ins.adsbygoogle',
    '[id*="ad-slot"]',
    '[class*="ad-slot"]',
    '[id*="ad_unit"]',
    '[class*="ad_unit"]',
    '[id*="ad-unit"]',
    '[class*="ad-unit"]',
    '[id*="ad-container"]',
    '[class*="ad-container"]',
    '[class*="ad-wrapper"]',
    '[id*="ad-wrapper"]',
    '[id*="interstitial"]',
    '[class*="interstitial"]',
    '[id*="overlay-ad"]',
    '[class*="overlay-ad"]',
    '[id*="popup-ad"]',
    '[class*="popup-ad"]',
    '[id*="popunder"]',
    '[class*="popunder"]',
    '[class*="ad-overlay"]',
    '[id*="ad-overlay"]',
    '[id*="ad_overlay"]',
    '[class*="modal-ad"]',
    '[id*="modal-ad"]',
    '[id*="anchor-ad"]',
    '[class*="anchor-ad"]',
    '[class*="sticky-ad"]',
    '[id*="sticky-ad"]',
    '[id*="bottom-ad"]',
    '[class*="bottom-ad"]',
    '[class*="sponsored"]',
    '[id*="sponsored"]',
    '[class*="taboola"]',
    '[id*="taboola"]',
    '[class*="outbrain"]',
    '[id*="outbrain"]',
    '[id*="trc_related"]',
    '[class*="video-ad"]',
    '[id*="video-ad"]',
    '[class*="video_ad"]',
    '[class*="native-ad"]',
    '[id*="native-ad"]',
    '[class*="floating-ad"]',
    '[id*="floating-ad"]',
    '[class*="ad-banner"]',
    '[id*="ad-banner"]',
    '[data-ad]',
    '[data-ad-slot]',
    '[data-google-query-id]',
    '[data-ad-client]',
    '[aria-label*="advertisement" i]',
    '[aria-label*="sponsored" i]',
    'iframe[src*="doubleclick"]',
    'iframe[src*="googlesyndication"]',
    'iframe[src*="googletagservices"]',
    'iframe[src*="adservice.google"]',
    'iframe[src*="taboola"]',
    'iframe[src*="outbrain"]',
    'iframe[src*="interstitial"]',
    'iframe[id*="ads"]',
    'iframe[src*="ads"]',
    'iframe[src*="adserver"]',
    'iframe[src*="advert"]',
    // CanYouBlockIt / D3ward / adblock-tester test elements
    '#canyoublockit',
    '#d3ward-test',
    '.ad-test',
    '.ad_test',
    '.adtest',
    '[class*="ad-placeholder"]',
    '[id*="ad-placeholder"]',
    '[class*="ad_placeholder"]',
    '[id*="ad_placeholder"]',
    // Cookie/consent ad overlays
    '[class*="cookie-banner"][class*="ad"]',
    '[id*="cookie-notice"][class*="ad"]',
    '[class*="gdpr"][class*="ad"]',
    '[class*="consent"][class*="overlay"][class*="ad"]',
    // Facebook / Instagram sponsored
    '[data-pagelet*="FeedUnit"][data-ad-preview]',
    'div[aria-label*="Sponsored" i]',
    'div[aria-label*="Paid partnership" i]',
    'article[data-testid="tweet"] [data-testid="placementTracking"]',
    // Twitter/X promoted
    '[data-testid="tweet"] [data-testid="promotedIndicator"]',
    '[data-testid="placementTracking"]',
    // Reddit promoted
    'shreddit-ad-post',
    '[data-testid="promoted-post"]',
    '.promotedlink',
    'div[data-adclicklocation]',
    // LinkedIn sponsored
    '.feed-shared-update-v2--is-sponsored',
    '.ad-banner-container',
    '.sponsored-update-v2',
    // Twitch ads
    '.video-player__overlay--ad',
    '.player-ad-overlay',
    '[data-a-target="player-ad-overlay"]',
    '.top-nav__prime',
    '.persistent-player',
    '[class*="stream-display-ad"]',
    // YouTube (feed-level; player handled by youtube.js)
    '.ytd-promoted-video-renderer',
    '.ytd-display-ad-renderer',
    '.ytd-ad-slot-renderer',
    '#masthead-ad',
  ];

  const GENERIC_SELECTORS = [
    '[id*="ad"]',
    '[id*="ads"]',
    '[id*="advert"]',
    '[class*="ad"]',
    '[class*="ads"]',
    '[class*="banner"]',
    '[class*="sponsor"]',
    '[class*="advert"]',
  ];

  const SAFE_SUBSTRINGS = [
    "header", "leader", "leading", "shadow", "gradient", "radar",
    "loading", "load", "grade", "upload", "download", "thread",
    "spread", "head", "ready", "already", "admin", "address",
    "adjust", "advance", "advanced", "advisor", "adapt", "adobe",
    "radio", "saddle", "trader", "trading", "broadcast", "broad",
    "ladder", "padding", "wad", "quad", "squad", "road", "android",
    "addon", "addition", "additional", "thread", "breadcrumb",
    "upload", "payload", "headline", "read", "thread",
  ];

  const EXPLICIT_AD_RE =
    /advert|sponsor|adsbygoogle|ad-slot|ad_slot|ad-unit|ad_unit|ad-banner|ad_banner|ad-container|ad_container|interstitial|popunder|anchor-ad|sticky-ad|\bads\b|\bad\b/;

  const SPECIFIC_SELECTOR_STR = SPECIFIC_SELECTORS.join(",");
  const GENERIC_SELECTOR_STR = GENERIC_SELECTORS.join(",");
  const CSS_RULE = SPECIFIC_SELECTORS.map((s) => s + "{display:none!important;visibility:hidden!important;pointer-events:none!important}").join("");

  const hiddenSet = typeof WeakSet !== "undefined" ? new WeakSet() : null;

  function injectCSS() {
    if (document.getElementById("webshield-cosmetic-css")) return;
    const style = document.createElement("style");
    style.id = "webshield-cosmetic-css";
    style.textContent = CSS_RULE;
    const target = document.documentElement || document.head || document.body;
    if (target) target.appendChild(style);
    log("CSS injected", SPECIFIC_SELECTORS.length, "rules");
  }

  function attrs(el) {
    const id = (el.id || "").toLowerCase();
    const cls =
      (el.className && typeof el.className === "string"
        ? el.className
        : el.getAttribute && el.getAttribute("class")) || "";
    return id + " " + String(cls).toLowerCase();
  }

  function isGenericFalsePositive(el) {
    const combined = attrs(el);
    if (EXPLICIT_AD_RE.test(combined)) return false;
    for (const safe of SAFE_SUBSTRINGS) {
      if (combined.includes(safe)) return true;
    }
    return false;
  }

  function isAlreadyHidden(el) {
    if (!el) return true;
    if (el.dataset && el.dataset.webshieldHidden === "1") return true;
    if (hiddenSet && hiddenSet.has(el)) return true;
    return false;
  }

  function hideElement(el, opts) {
    opts = opts || {};
    if (!el || isAlreadyHidden(el)) return;
    if (el === document.documentElement || el === document.body) return;
    if (el.id === "webshield-warning" || el.id === "webshield-cosmetic-css") return;
    if (!opts.force && isGenericFalsePositive(el)) return;

    el.style.setProperty("display", "none", "important");
    el.style.setProperty("visibility", "hidden", "important");
    el.style.setProperty("pointer-events", "none", "important");
    el.style.setProperty("height", "0", "important");
    el.style.setProperty("max-height", "0", "important");
    el.style.setProperty("overflow", "hidden", "important");
    if (el.dataset) el.dataset.webshieldHidden = "1";
    if (hiddenSet) hiddenSet.add(el);

    hideCount++;
    log("Hidden", el.tagName, attrs(el));

    try {
      chrome.runtime.sendMessage({ action: "cosmeticHide", tag: el.tagName });
    } catch {
      // extension context may be invalidated
    }
  }

  function scanSpecific(root) {
    if (!root || !root.querySelectorAll) return;
    let nodes;
    try {
      nodes = root.querySelectorAll(SPECIFIC_SELECTOR_STR);
    } catch {
      return;
    }
    for (let i = 0; i < nodes.length; i++) hideElement(nodes[i], { force: true });
  }

  function scanGeneric(root) {
    if (!root || !root.querySelectorAll) return;
    let nodes;
    try {
      nodes = root.querySelectorAll(GENERIC_SELECTOR_STR);
    } catch {
      return;
    }
    for (let i = 0; i < nodes.length; i++) hideElement(nodes[i]);
  }

  // ── Full-screen overlay / interstitial heuristic ───────────────────────────
  function scanOverlays() {
    const vw = window.innerWidth;
    const vh = window.innerHeight;
    if (vw === 0 || vh === 0 || !document.body) return;

    const candidates = document.body.querySelectorAll("div, section, aside, dialog, [role='dialog']");

    for (let i = 0; i < candidates.length; i++) {
      const el = candidates[i];
      if (isAlreadyHidden(el)) continue;
      if (el === document.body || el === document.documentElement) continue;

      let style;
      try {
        style = window.getComputedStyle(el);
      } catch {
        continue;
      }
      if (!style) continue;

      const position = style.position;
      if (position !== "fixed" && position !== "sticky" && position !== "absolute") continue;

      const zIndex = parseInt(style.zIndex, 10);
      if (isNaN(zIndex) || zIndex < 500) continue;

      const rect = el.getBoundingClientRect();
      if (rect.width === 0 || rect.height === 0) continue;

      const coversWidth = rect.width >= vw * 0.75;
      const coversHeight = rect.height >= vh * 0.5;

      if (coversWidth && coversHeight) {
        const combined = attrs(el);
        const looksLikeAd =
          EXPLICIT_AD_RE.test(combined) ||
          /overlay|popup|modal|interstitial|lightbox|backdrop|consent|cookie|gdpr|subscribe|newsletter|paywall/i.test(combined);

        const textLen = (el.innerText || "").length;
        const bodyTextLen = (document.body.innerText || "").length;
        const isMainContent = bodyTextLen > 0 && textLen / bodyTextLen > 0.85;

        if (looksLikeAd || (!isMainContent && zIndex >= 1000)) {
          hideElement(el, { force: true });
          restorePageScroll();
          log("Overlay removed", combined.slice(0, 80));
        }
      }
    }
  }

  // ── Click-blocking trap layers ─────────────────────────────────────────────
  function scanClickTraps() {
    if (!document.body) return;
    const traps = document.body.querySelectorAll("div, section");
    for (let i = 0; i < traps.length; i++) {
      const el = traps[i];
      if (isAlreadyHidden(el)) continue;
      let style;
      try {
        style = window.getComputedStyle(el);
      } catch {
        continue;
      }
      if (style.position !== "fixed" && style.position !== "absolute") continue;
      if (parseInt(style.zIndex, 10) < 9999) continue;
      if (style.pointerEvents === "none") continue;

      const rect = el.getBoundingClientRect();
      const vw = window.innerWidth;
      const vh = window.innerHeight;
      if (rect.width < vw * 0.9 || rect.height < vh * 0.9) continue;

      const hasVisibleChildren = el.querySelector("img, video, iframe, a, button, input, p, h1, h2, h3");
      const textLen = (el.innerText || "").trim().length;
      if (!hasVisibleChildren && textLen < 20) {
        hideElement(el, { force: true });
        restorePageScroll();
        log("Click-trap removed");
      }
    }
  }

  function restorePageScroll() {
    [document.documentElement, document.body].forEach((el) => {
      if (!el) return;
      let style;
      try {
        style = window.getComputedStyle(el);
      } catch {
        return;
      }
      if (style.overflow === "hidden" || style.position === "fixed") {
        el.style.setProperty("overflow", "auto", "important");
        el.style.setProperty("position", "static", "important");
        el.style.setProperty("height", "auto", "important");
        el.classList.remove("no-scroll", "modal-open", "overflow-hidden", "noscroll");
      }
    });
  }

  // ── Shadow DOM piercing ────────────────────────────────────────────────────
  function scanShadowRoots(root) {
    if (!root || !root.querySelectorAll) return;
    const hosts = root.querySelectorAll("*");
    for (let i = 0; i < hosts.length; i++) {
      const host = hosts[i];
      if (host.shadowRoot) {
        scanSpecific(host.shadowRoot);
        scanGeneric(host.shadowRoot);
        scanShadowRoots(host.shadowRoot);
      }
    }
  }

  function runFullScan(root) {
    root = root || document;
    scanSpecific(root);
    scanGeneric(root);
    scanOverlays();
    scanClickTraps();
    scanShadowRoots(root);
  }

  function scheduleScan() {
    if (pendingScan) return;
    pendingScan = true;
    if (debounceTimer) clearTimeout(debounceTimer);
    debounceTimer = setTimeout(() => {
      pendingScan = false;
      // Batch DOM ops in rAF to minimize layout thrashing
      if (typeof requestAnimationFrame === "function") {
        requestAnimationFrame(() => runFullScan(document));
      } else {
        runFullScan(document);
      }
    }, 120);
  }

  // ── SPA / React / Angular navigation hooks ─────────────────────────────────
  function hookSPA() {
    const fire = () => setTimeout(() => runFullScan(document), 50);

    window.addEventListener("popstate", fire);
    window.addEventListener("hashchange", fire);

    const origPush = history.pushState;
    const origReplace = history.replaceState;
    history.pushState = function () {
      const r = origPush.apply(this, arguments);
      fire();
      return r;
    };
    history.replaceState = function () {
      const r = origReplace.apply(this, arguments);
      fire();
      return r;
    };

    // React/Angular often use MutationObserver on root — also poll briefly after nav
    document.addEventListener("DOMContentLoaded", fire);
    window.addEventListener("load", fire);
  }

  function boot() {
    if (observer) return;
    injectCSS();

    const initScan = () => runFullScan(document);
    if (document.readyState === "loading") {
      document.addEventListener("DOMContentLoaded", initScan, { once: true });
    } else {
      initScan();
    }

    hookSPA();

    observer = new MutationObserver((mutations) => {
      let needsFull = false;
      for (const mutation of mutations) {
        if (mutation.type === "childList") {
          for (let i = 0; i < mutation.addedNodes.length; i++) {
            const node = mutation.addedNodes[i];
            if (node.nodeType !== 1) continue;
            try {
              if (node.matches && node.matches(SPECIFIC_SELECTOR_STR)) {
                hideElement(node, { force: true });
              } else if (node.matches && node.matches(GENERIC_SELECTOR_STR)) {
                hideElement(node);
              }
            } catch {
              // ignore invalid selector match
            }
            scanSpecific(node);
            scanGeneric(node);
            if (node.shadowRoot) scanShadowRoots(node);
            needsFull = true;
          }
        } else if (mutation.type === "attributes") {
          const target = mutation.target;
          if (target.nodeType === 1) {
            try {
              if (target.matches && target.matches(SPECIFIC_SELECTOR_STR)) {
                hideElement(target, { force: true });
              } else if (target.matches && target.matches(GENERIC_SELECTOR_STR)) {
                hideElement(target);
              }
            } catch {
              // ignore
            }
            needsFull = true;
          }
        }
      }
      if (needsFull) scheduleScan();
    });

    const observeTarget = document.documentElement || document.body;
    if (observeTarget) {
      observer.observe(observeTarget, {
        childList: true,
        subtree: true,
        attributes: true,
        attributeFilter: ["id", "class", "src", "style", "data-ad", "data-ad-slot"],
      });
    }

    // Periodic fallback for timed interstitials and async frameworks
    let scanCount = 0;
    periodicTimer = setInterval(() => {
      runFullScan(document);
      scanCount++;
      if (scanCount > 45) clearInterval(periodicTimer);
    }, 1000);

    log("Cosmetic engine started");
  }
})();
