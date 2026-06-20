# WebShield.AI v3.0 — Migration Guide

## Overview

WebShield.AI v3.0 refactors the monolithic extension into a modular, enterprise-grade architecture comparable to uBlock Origin, AdGuard, and Brave Shields.

## File Structure

```
extension/
├── manifest.json          # MV3 manifest (v3.0.0)
├── background.js          # Service worker orchestrator
├── content.js             # Page security orchestrator
├── adblock.js             # Public API (enable/disable, stats)
├── rules-engine.js        # DNR static + dynamic rules
├── tracker.js             # Request classification
├── stats.js               # Analytics & badge
├── security.js            # Malware/phishing/redirect (background)
├── cosmetic.js            # DOM cosmetic filtering
├── youtube.js             # YouTube ad removal engine
├── antiadblock.js         # Anti-adblock countermeasures
├── generate-rules.js      # Rule list generator
├── rules.json             # EasyList/EasyPrivacy (28K rules)
├── rules-platform.json    # YouTube/Twitch/Social rules
├── rules-security.json    # Miners/fingerprinting/malware
├── popup.html / popup.js  # UI (unchanged API)
└── ...

lib/
└── webshield-utils.js     # Testable shared utilities

tests/
└── webshield.test.js      # Unit tests

benchmarks/
└── run.js                 # Performance benchmarks
```

## Breaking Changes

| v2.x | v3.0 |
|------|------|
| Single `ruleset_1` | Three rulesets: `ruleset_1`, `ruleset_platform`, `ruleset_security` |
| Cosmetic-only content script | Four content scripts: `content.js`, `cosmetic.js`, `youtube.js`, `antiadblock.js` |
| `totalAds` / `totalTrackers` only | Extended stats: malware, phishing, fingerprint, miners, privacy score |
| Ad logic in `background.js` | Split across `tracker.js`, `stats.js`, `rules-engine.js` |

## Upgrade Steps

### 1. Reload the extension

```bash
# Regenerate filter lists (optional, requires network)
npm run generate-rules

# Run tests
npm test

# Run benchmarks
npm run benchmark
```

In Chrome: `chrome://extensions` → WebShield.AI → **Reload**

### 2. Verify rulesets loaded

Open the extension service worker console and confirm:

```
[WebShield AdBlock] Ad blocker enabled
[WebShield AdBlock] Rules optimized: { removed: N, remaining: M }
```

Or call from popup devtools:

```js
chrome.runtime.sendMessage({ action: "getDnrDiagnostics" }, console.log);
```

Expected: `enabledRulesets` includes `ruleset_1`, `ruleset_platform`, `ruleset_security`.

### 3. Test platform blocking

| Platform | Network (DNR) | Cosmetic / Script |
|----------|---------------|-------------------|
| YouTube | `rules-platform.json` + dynamic rules | `youtube.js` (skip, 16x, overlays) |
| Twitch | `rules-platform.json` | `cosmetic.js` selectors |
| Facebook/Instagram | Tracker blocking | Sponsored post selectors |
| Twitter/X | `static.ads-twitter.com` blocked | Promoted tweet selectors |
| Reddit | `reddit.com/api/v1/ads` blocked | `shreddit-ad-post` hidden |
| LinkedIn | `ads.linkedin.com` blocked | Sponsored feed selectors |

### 4. Popup compatibility

`popup.js` continues to use `enableAdBlocker()`, `disableAdBlocker()`, `getBlockedAdsCount()`, and `resetBlockedAdsCount()` from `adblock.js` — no popup changes required.

New stats available via:

```js
chrome.runtime.sendMessage({ action: "getStats" }, console.log);
```

## New Message Actions

| Action | Direction | Purpose |
|--------|-----------|---------|
| `getStats` | content/popup → background | Full analytics payload |
| `optimizeRules` | popup → background | Dedupe dynamic rules |
| `antiAdblockRemoved` | antiadblock.js → background | Counter anti-adblock stat |
| `blockPopup` | content.js → background | Popunder blocked |
| `suspiciousForm` | content.js → background | Credential harvesting detected |
| `pageLoadTime` | content.js → background | Page load analytics |

## Firefox Compatibility

`manifest.json` includes `browser_specific_settings.gecko` for Firefox 109+. Note:

- `declarativeNetRequest` API is supported in Firefox 113+
- `onRuleMatchedDebug` may not be available — falls back to `webRequest` counting
- Dynamic rule limit may differ

## Performance Tuning

- **100+ tabs**: Stats use batched promise queue; request dedup via `requestId` Set with 60s TTL
- **DOM**: Cosmetic engine debounces mutations (120ms) and batches via `requestAnimationFrame`
- **YouTube**: Dedicated 250ms tick with skip-click + 16x playback acceleration
- **Memory**: Periodic cosmetic scan stops after 45 intervals; WeakSet for hidden elements

## Regenerating Rules

```bash
cd extension
node generate-rules.js
```

This fetches EasyList, EasyPrivacy, NoCoin, URLhaus and writes `rules.json` (max 28,000 rules).

Platform and security rulesets are maintained in `rules-platform-data.js` and `rules-security.json`.

## Rollback

To revert to v2.x architecture:

```bash
git checkout add-blocker -- extension/
```

Or disable new rulesets in `manifest.json` and remove extra content scripts.

## Support

- Debug mode: `chrome.storage.local.set({ adBlockDebug: true })`
- DNR diagnostics: `{ action: "getDnrDiagnostics" }`
- Rule optimization: `{ action: "optimizeRules" }`
