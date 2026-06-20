// WebShield.AI — YouTube Ad Removal Engine
// Blocks pre-roll, mid-roll, overlay, Shorts, sponsored cards, and end-screen promos.

(function () {
  "use strict";

  if (window.__webshieldYouTube) return;
  window.__webshieldYouTube = true;

  const HOST = location.hostname;
  if (!/youtube\.com|youtu\.be|m\.youtube\.com|music\.youtube\.com/.test(HOST)) return;

  let enabled = true;
  let youtubeAdEnabled = false;
  let tickTimer = null;
  let savedPlaybackRate = 1;
  let savedMuted = false;
  let adActive = false;
  let hideCount = 0;
  let mutationObserver = null;
  let ytNavigateListener = null;
  let ytPageDataListener = null;

  const AD_SELECTORS = [
    ".ytp-ad-module",
    ".ytp-ad-player-overlay",
    ".ytp-ad-image-overlay",
    ".ytp-ad-text",
    ".ytp-ad-preview-container",
    ".ytp-ad-skip-button-slot",
    ".ytp-ce-element",
    ".ad-showing",
    ".ytd-promoted-video-renderer",
    ".ytd-display-ad-renderer",
    ".ytd-ad-slot-renderer",
    ".ytd-in-feed-ad-layout-renderer",
    ".ytd-banner-promo-renderer",
    ".ytd-primetime-promo-renderer",
    ".ytd-statement-banner-renderer",
    ".ytd-compact-promoted-video-renderer",
    ".ytd-promoted-sparkles-web-renderer",
    ".ytd-promoted-sparkles-text-search-renderer",
    ".ytp-ad-overlay-container",
    ".ytp-ad-progress-list",
    ".video-ads",
    ".ytp-ad-action-interstitial",
    "#player-ads",
    "#masthead-ad",
    "ytd-rich-item-renderer[is-ad]",
    "ytd-reel-video-renderer[is-ad]",
  ];

  const AD_CSS = AD_SELECTORS.map(
    (s) => `${s}{display:none!important;visibility:hidden!important;height:0!important;overflow:hidden!important}`,
  ).join("");

  try {
    chrome.storage.local.get({ adBlockEnabled: true, youtubeAdBlockEnabled: false }, (res) => {
      if (res.adBlockEnabled === false) {
        console.log("[WebShield] Ad blocker disabled, YouTube blocker disabled");
        teardown();
        return;
      }
      youtubeAdEnabled = res.youtubeAdBlockEnabled === true;
      if (!youtubeAdEnabled) {
        console.log("[WebShield] YouTube blocker disabled via toggle");
        teardown();
        return;
      }
      console.log("[WebShield] YouTube blocker enabled");
      boot();
    });
    chrome.storage.onChanged.addListener((changes, area) => {
      if (area === "local" && changes.adBlockEnabled) {
        enabled = changes.adBlockEnabled.newValue !== false;
        if (!enabled) {
          console.log("[WebShield] Ad blocker disabled, YouTube blocker disabled");
          teardown();
        } else if (youtubeAdEnabled) {
          console.log("[WebShield] Ad blocker enabled, YouTube blocker enabled");
          boot();
        }
      }
      if (area === "local" && changes.youtubeAdBlockEnabled) {
        youtubeAdEnabled = changes.youtubeAdBlockEnabled.newValue === true;
        if (!youtubeAdEnabled) {
          console.log("[WebShield] YouTube blocker disabled via toggle");
          teardown();
        } else if (enabled) {
          console.log("[WebShield] YouTube blocker enabled via toggle");
          boot();
        }
      }
    });
  } catch { /* no storage */ }

  function reportBlock(tag) {
    hideCount++;
    try {
      chrome.runtime.sendMessage({ action: "cosmeticHide", tag: tag || "youtube" });
    } catch { /* context invalidated */ }
  }

  function injectCSS() {
    if (document.getElementById("webshield-yt-css")) return;
    const style = document.createElement("style");
    style.id = "webshield-yt-css";
    style.textContent = AD_CSS;
    (document.documentElement || document.head).appendChild(style);
  }

  function getVideo() {
    return document.querySelector("video.html5-main-video, video");
  }

  function getPlayer() {
    return document.querySelector(".html5-video-player, #movie_player");
  }

  function isAdShowing() {
    const player = getPlayer();
    if (player && player.classList.contains("ad-showing")) return true;
    if (player && player.classList.contains("ad-interrupting")) return true;
    if (document.querySelector(".ytp-ad-module, .ytp-ad-player-overlay, .ad-showing")) return true;
    const video = getVideo();
    if (video) {
      // YouTube marks ads in video title overlay
      const title = document.querySelector(".ytp-ad-text, .ytp-ad-preview-text");
      if (title) return true;
    }
    return false;
  }

  function clickSkipButton() {
    const skip = document.querySelector(
      ".ytp-ad-skip-button, .ytp-ad-skip-button-modern, .ytp-skip-ad-button, button.ytp-ad-skip-button-slot",
    );
    if (skip) {
      skip.click();
      reportBlock("yt-skip");
      return true;
    }
    return false;
  }

  function removeOverlays() {
    let removed = false;
    for (const sel of AD_SELECTORS) {
      document.querySelectorAll(sel).forEach((el) => {
        el.remove();
        removed = true;
        reportBlock("yt-overlay");
      });
    }
    return removed;
  }

  function accelerateAd() {
    const video = getVideo();
    if (!video) return;
    if (!adActive) {
      savedPlaybackRate = video.playbackRate || 1;
      savedMuted = video.muted;
      adActive = true;
    }
    video.muted = true;
    try { video.playbackRate = 16; } catch { video.playbackRate = 8; }
    // Jump near end if duration known
    if (video.duration && isFinite(video.duration) && video.duration < 120) {
      if (video.currentTime < video.duration - 0.5) {
        video.currentTime = Math.max(0, video.duration - 0.1);
      }
    }
  }

  function restorePlayback() {
    if (!adActive) return;
    adActive = false;
    const video = getVideo();
    if (!video) return;
    try { video.playbackRate = savedPlaybackRate || 1; } catch { video.playbackRate = 1; }
    video.muted = savedMuted;
  }

  function hideSponsoredFeed() {
    document.querySelectorAll(
      "ytd-rich-item-renderer, ytd-video-renderer, ytd-reel-item-renderer, ytd-compact-video-renderer",
    ).forEach((el) => {
      const badge = el.querySelector(
        "[aria-label*='Sponsored' i], [aria-label*='Promoted' i], .badge-style-type-ad, ytd-badge-supported-renderer",
      );
      const text = (el.innerText || "").toLowerCase();
      if (badge || text.includes("sponsored") || text.includes("promoted")) {
        el.style.display = "none";
        reportBlock("yt-sponsored");
      }
    });
  }

  function tick() {
    if (!enabled || !youtubeAdEnabled) return;
    injectCSS();
    removeOverlays();
    hideSponsoredFeed();

    if (isAdShowing()) {
      clickSkipButton();
      accelerateAd();
    } else {
      restorePlayback();
    }
  }

  function boot() {
    if (tickTimer) return;
    injectCSS();
    tick();
    tickTimer = setInterval(tick, 250);

    mutationObserver = new MutationObserver(() => tick());
    const target = document.documentElement;
    if (target) {
      mutationObserver.observe(target, { childList: true, subtree: true, attributes: true,
        attributeFilter: ["class", "src"] });
    }

    // Hook SPA navigation
    ytNavigateListener = () => tick();
    ytPageDataListener = () => tick();
    window.addEventListener("yt-navigate-finish", ytNavigateListener);
    window.addEventListener("yt-page-data-updated", ytPageDataListener);
  }

  function teardown() {
    if (tickTimer) { clearInterval(tickTimer); tickTimer = null; }
    restorePlayback();
    // Disconnect MutationObserver
    if (mutationObserver) {
      mutationObserver.disconnect();
      mutationObserver = null;
    }
    // Remove event listeners
    if (ytNavigateListener) {
      window.removeEventListener("yt-navigate-finish", ytNavigateListener);
      ytNavigateListener = null;
    }
    if (ytPageDataListener) {
      window.removeEventListener("yt-page-data-updated", ytPageDataListener);
      ytPageDataListener = null;
    }
    // Remove injected CSS
    const style = document.getElementById("webshield-yt-css");
    if (style) style.remove();
    // Restore hidden elements
    for (const sel of AD_SELECTORS) {
      document.querySelectorAll(sel).forEach((el) => {
        el.style.display = "";
        el.style.visibility = "";
        el.style.height = "";
        el.style.overflow = "";
      });
    }
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", boot, { once: true });
  } else {
    boot();
  }
})();
