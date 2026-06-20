// WebShield.AI — DeclarativeNetRequest Rules Engine
// Manages static rulesets, dynamic rules, priorities, and rule optimization.

const WS_DYNAMIC_RULE_BASE = 900000;
const WS_MAX_DYNAMIC_RULES = 5000;
const WS_STATIC_RULESET_IDS = ["ruleset_1", "ruleset_platform", "ruleset_security"];
const WS_YOUTUBE_RULESET_ID = "ruleset_youtube";

const WS_RESOURCE_TYPES = [
  "script", "image", "media", "font", "xmlhttprequest",
  "websocket", "ping", "sub_frame", "object", "other",
];

// YouTube-specific dynamic rule IDs (no longer used, YouTube rules now in separate ruleset)
const WS_YOUTUBE_RULE_IDS = [];

// High-priority dynamic rules for platforms (installed at startup)
const WS_PLATFORM_DYNAMIC_RULES = [
  // Twitch
  { id: 900010, priority: 18, filter: "||amazon-adsystem.com^", types: WS_RESOURCE_TYPES },
  { id: 900011, priority: 18, filter: "||twitch.tv/ads^", types: WS_RESOURCE_TYPES },
  { id: 900012, priority: 18, filter: "||twitchcdn.net/ads^", types: WS_RESOURCE_TYPES },
  // Social sponsored tracking
  { id: 900020, priority: 15, filter: "||facebook.com/tr^", types: WS_RESOURCE_TYPES },
  { id: 900021, priority: 15, filter: "||static.ads-twitter.com^", types: WS_RESOURCE_TYPES },
  { id: 900022, priority: 15, filter: "||ads-api.twitter.com^", types: WS_RESOURCE_TYPES },
  { id: 900023, priority: 15, filter: "||ads.linkedin.com^", types: WS_RESOURCE_TYPES },
  { id: 900024, priority: 15, filter: "||reddit.com/api/v1/ads^", types: WS_RESOURCE_TYPES },
  // Crypto miners
  { id: 900030, priority: 25, filter: "||coinhive.com^", types: WS_RESOURCE_TYPES },
  { id: 900031, priority: 25, filter: "||coin-hive.com^", types: WS_RESOURCE_TYPES },
  { id: 900032, priority: 25, filter: "||crypto-loot.com^", types: WS_RESOURCE_TYPES },
  { id: 900033, priority: 25, filter: "||coinimp.com^", types: WS_RESOURCE_TYPES },
  // Fingerprinting
  { id: 900040, priority: 22, filter: "||fingerprintjs.com^", types: WS_RESOURCE_TYPES },
  { id: 900041, priority: 22, filter: "||fpjs.io^", types: WS_RESOURCE_TYPES },
  { id: 900042, priority: 22, filter: "||clientjs.org^", types: WS_RESOURCE_TYPES },
  // Popunder / redirect ads
  { id: 900050, priority: 19, filter: "||popads.net^", types: WS_RESOURCE_TYPES },
  { id: 900051, priority: 19, filter: "||popcash.net^", types: WS_RESOURCE_TYPES },
  { id: 900052, priority: 19, filter: "||propellerads.com^", types: WS_RESOURCE_TYPES },
  { id: 900053, priority: 19, filter: "||adsterra.com^", types: WS_RESOURCE_TYPES },
  // Anti-adblock scripts (common)
  { id: 900060, priority: 17, filter: "||blockadblock.com^", types: ["script"] },
  { id: 900061, priority: 17, filter: "||antiadblocksystems.com^", types: ["script"] },
  { id: 900062, priority: 17, filter: "||detectadblock.com^", types: ["script"] },
  // Cookie consent spam (Fanboy annoyance subset)
  { id: 900070, priority: 12, filter: "||cdn.cookielaw.org^", types: ["script", "xmlhttprequest"] },
  { id: 900071, priority: 12, filter: "||consent.cookiebot.com^", types: ["script", "xmlhttprequest"] },
  { id: 900072, priority: 12, filter: "||onetrust.com^", types: ["script", "xmlhttprequest"] },
];

function wsBuildDynamicRule(spec) {
  return {
    id: spec.id,
    priority: spec.priority || 10,
    action: { type: "block" },
    condition: {
      urlFilter: spec.filter,
      resourceTypes: spec.types || WS_RESOURCE_TYPES,
    },
  };
}

async function wsInstallDynamicRules() {
  try {
    const existing = await chrome.declarativeNetRequest.getDynamicRules();
    const existingIds = new Set(existing.map((r) => r.id));
    const toAdd = WS_PLATFORM_DYNAMIC_RULES
      .filter((spec) => !existingIds.has(spec.id))
      .map(wsBuildDynamicRule);

    if (toAdd.length === 0) return { added: 0 };

    await chrome.declarativeNetRequest.updateDynamicRules({ addRules: toAdd });
    return { added: toAdd.length };
  } catch (err) {
    console.error("[WebShield Rules]", err);
    return { added: 0, error: err.message };
  }
}

async function wsEnableAllRulesets() {
  try {
    return await chrome.declarativeNetRequest.updateEnabledRulesets({
      enableRulesetIds: WS_STATIC_RULESET_IDS,
    });
  } catch (err) {
    // Fallback: enable primary ruleset only if platform/security not yet installed
    return chrome.declarativeNetRequest.updateEnabledRulesets({
      enableRulesetIds: ["ruleset_1"],
    });
  }
}

async function wsDisableAllRulesets() {
  try {
    return await chrome.declarativeNetRequest.updateEnabledRulesets({
      disableRulesetIds: WS_STATIC_RULESET_IDS,
    });
  } catch (err) {
    return chrome.declarativeNetRequest.updateEnabledRulesets({
      disableRulesetIds: ["ruleset_1"],
    });
  }
}

async function wsAddDynamicRule(urlFilter, options) {
  options = options || {};
  const existing = await chrome.declarativeNetRequest.getDynamicRules();
  if (existing.length >= WS_MAX_DYNAMIC_RULES) return null;

  const id = options.id || WS_DYNAMIC_RULE_BASE + existing.length + 1;
  const rule = wsBuildDynamicRule({
    id,
    filter: urlFilter,
    priority: options.priority || 10,
    types: options.resourceTypes || WS_RESOURCE_TYPES,
  });

  await chrome.declarativeNetRequest.updateDynamicRules({ addRules: [rule] });
  return id;
}

async function wsRemoveDynamicRule(ruleId) {
  await chrome.declarativeNetRequest.updateDynamicRules({ removeRuleIds: [ruleId] });
}

async function wsOptimizeRules() {
  try {
    const dynamic = await chrome.declarativeNetRequest.getDynamicRules();
    // Remove duplicate urlFilters keeping highest priority
    const seen = new Map();
    const toRemove = [];

    for (const rule of dynamic) {
      const key = rule.condition.urlFilter || rule.condition.regexFilter || "";
      if (!key) continue;
      const prev = seen.get(key);
      if (prev) {
        toRemove.push(rule.priority < prev.priority ? rule.id : prev.id);
        if (rule.priority >= prev.priority) seen.set(key, rule);
      } else {
        seen.set(key, rule);
      }
    }

    if (toRemove.length) {
      await chrome.declarativeNetRequest.updateDynamicRules({
        removeRuleIds: [...new Set(toRemove)],
      });
    }
    return { removed: toRemove.length, remaining: dynamic.length - toRemove.length };
  } catch (err) {
    return { removed: 0, error: err.message };
  }
}

async function wsGetRulesDiagnostics() {
  const [enabled, available, dynamic, matched] = await Promise.all([
    chrome.declarativeNetRequest.getEnabledRulesets(),
    chrome.declarativeNetRequest.getAvailableStaticRuleCount
      ? chrome.declarativeNetRequest.getAvailableStaticRuleCount()
      : Promise.resolve(null),
    chrome.declarativeNetRequest.getDynamicRules(),
    chrome.declarativeNetRequest.getMatchedRules
      ? chrome.declarativeNetRequest.getMatchedRules({ minTimeStamp: 0 })
      : Promise.resolve({ rulesMatchedInfo: [] }),
  ]);

  return {
    enabledRulesets: enabled,
    availableStaticRuleCount: available,
    dynamicRulesCount: dynamic.length,
    matchedRulesCount: matched.rulesMatchedInfo ? matched.rulesMatchedInfo.length : 0,
  };
}

async function enableYoutubeRules() {
  try {
    console.log("[WebShield] Enabling YouTube DNR ruleset");
    await chrome.declarativeNetRequest.updateEnabledRulesets({
      enableRulesetIds: [WS_YOUTUBE_RULESET_ID],
    });
    console.log("[WebShield] YouTube DNR ruleset enabled");
    return { enabled: true };
  } catch (err) {
    console.error("[WebShield YouTube Rules]", err);
    return { enabled: false, error: err.message };
  }
}

async function disableYoutubeRules() {
  try {
    console.log("[WebShield] Disabling YouTube DNR ruleset");
    await chrome.declarativeNetRequest.updateEnabledRulesets({
      disableRulesetIds: [WS_YOUTUBE_RULESET_ID],
    });
    console.log("[WebShield] YouTube DNR ruleset disabled");
    return { disabled: true };
  } catch (err) {
    console.error("[WebShield YouTube Rules]", err);
    return { disabled: false, error: err.message };
  }
}
