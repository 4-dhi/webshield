#!/usr/bin/env node
/**
 * WebShield.AI — DNR rules generator
 * Converts EasyList, EasyPrivacy, and supplemental filter lists into
 * Chrome Manifest V3 declarativeNetRequest rules (rules.json).
 *
 * Usage: node generate-rules.js
 */

const fs = require("fs");
const path = require("path");
const https = require("https");
const http = require("http");

const OUTPUT = path.join(__dirname, "rules.json");
const OUTPUT_PLATFORM = path.join(__dirname, "rules-platform.json");
const OUTPUT_SECURITY = path.join(__dirname, "rules-security.json");
const MAX_RULES = 28000;

const RESOURCE_TYPES = [
  "script",
  "image",
  "media",
  "font",
  "xmlhttprequest",
  "websocket",
  "ping",
  "sub_frame",
  "object",
  "other",
];

const FILTER_LISTS = [
  { name: "EasyList", url: "https://easylist.to/easylist/easylist.txt", priority: 1 },
  { name: "EasyPrivacy", url: "https://easylist.to/easylist/easyprivacy.txt", priority: 1 },
  {
    name: "EasyList Germany",
    url: "https://easylist.to/easylistgermany/easylistgermany.txt",
    priority: 1,
  },
  {
    name: "EasyList Italy",
    url: "https://easylist-downloads.adblockplus.org/easylistitaly.txt",
    priority: 1,
  },
  {
    name: "EasyList Dutch",
    url: "https://easylist-downloads.adblockplus.org/easylistdutch.txt",
    priority: 1,
  },
  {
    name: "EasyList Spanish",
    url: "https://easylist-downloads.adblockplus.org/easylistspanish.txt",
    priority: 1,
  },
  {
    name: "Fanboy Annoyance",
    url: "https://easylist.to/easylist/fanboy-annoyance.txt",
    priority: 2,
  },
  {
    name: "NoCoin",
    url: "https://raw.githubusercontent.com/hoshsadiq/adblock-nocoin-list/master/nocoin.txt",
    priority: 2,
  },
  {
    name: "URLhaus",
    url: "https://malware-filter.gitlab.io/malware-filter/urlhaus-filter-online.txt",
    priority: 2,
  },
];

// High-priority explicit tracker / ad endpoints (D3ward, CanYouBlockIt, BrowserLeaks)
const EXPLICIT_PATTERNS = [
  "||doubleclick.net^",
  "||googlesyndication.com^",
  "||googleadservices.com^",
  "||googletagservices.com^",
  "||google-analytics.com^",
  "||analytics.google.com^",
  "||stats.g.doubleclick.net^",
  "||adservice.google.com^",
  "||pagead2.googlesyndication.com^",
  "||tpc.googlesyndication.com^",
  "||securepubads.g.doubleclick.net^",
  "||connect.facebook.net^",
  "||facebook.com/tr^",
  "||facebook.com/tr/*",
  "||pixel.facebook.com^",
  "||taboola.com^",
  "||trc.taboola.com^",
  "||outbrain.com^",
  "||widgets.outbrain.com^",
  "||criteo.com^",
  "||criteo.net^",
  "||adroll.com^",
  "||amazon-adsystem.com^",
  "||hotjar.com^",
  "||static.hotjar.com^",
  "||mixpanel.com^",
  "||cdn.mxpnl.com^",
  "||segment.io^",
  "||cdn.segment.com^",
  "||api.segment.io^",
  "||appsflyer.com^",
  "||adjust.com^",
  "||popads.net^",
  "||popcash.net^",
  "||propellerads.com^",
  "||adsterra.com^",
  "||exoclick.com^",
  "||juicyads.com^",
  "||mgid.com^",
  "||revcontent.com^",
  "||adnxs.com^",
  "||adsrvr.org^",
  "||rubiconproject.com^",
  "||pubmatic.com^",
  "||openx.net^",
  "||casalemedia.com^",
  "||smartadserver.com^",
  "||media.net^",
  "||moatads.com^",
  "||2mdn.net^",
  "||adform.net^",
  "||bidswitch.net^",
  "||quantserve.com^",
  "||scorecardresearch.com^",
  "||optimizely.com^",
  "||fullstory.com^",
  "||amplitude.com^",
  "||heapanalytics.com^",
  "||chartbeat.com^",
  "||demdex.net^",
  "||bluekai.com^",
  "||branch.io^",
  "||ad.doubleclick.net^",
  "||static.ads-twitter.com^",
  "||ads-twitter.com^",
  "||ads.linkedin.com^",
  "||snap.licdn.com^",
  "||bat.bing.com^",
  "||clarity.ms^",
  "||cdn.cookielaw.org^",
  "||onetag-sys.com^",
  "||yieldmo.com^",
  "||lijit.com^",
  "||sharethrough.com^",
  "||triplelift.com^",
  "||teads.tv^",
  "||spotxchange.com^",
  "||spotx.tv^",
  "||springserve.com^",
  "||contextweb.com^",
  "||adtech.de^",
  "||serving-sys.com^",
  "||adsafeprotected.com^",
  "||doubleverify.com^",
  "||imrworldwide.com^",
  "||krxd.net^",
  "||exelator.com^",
  "||tapad.com^",
  "||mathtag.com^",
  "||lotame.com^",
  "||adobedtm.com^",
  "||omtrdc.net^",
  "||2o7.net^",
  "||everesttech.net^",
  "||rlcdn.com^",
  "||agkn.com^",
  "||turn.com^",
  "||simpli.fi^",
  "||sitescout.com^",
  "||bidr.io^",
  "||crwdcntrl.net^",
  "||eyeota.net^",
  "||mfadsrvr.com^",
  "||admanmedia.com^",
  "||minero.cc^",
  "||coinhive.com^",
  "||coin-hive.com^",
  "||authedmine.com^",
  "||crypto-loot.com^",
  "||jsecoin.com^",
  "||ppoi.org^",
  "||coinerra.com^",
  "||monero-miner.com^",
  "||/ads.js",
  "||/advert.js",
  "||/advertisement.js",
  "||/banner.js",
  "||/popup.js",
  "||/popunder.js",
  "||/interstitial.js",
  "||/analytics.js",
  "||/gtag/js",
  "||/ga.js",
  "||/fbevents.js",
  "||/pixel.js",
  "||/tracking.js",
  "||/tracker.js",
  "||/beacon.js",
  "||/collect?",
  "||/pagead/",
  "||/pagead2/",
  "||/ads?",
  "||/adserver/",
  "||/ad-server/",
  "||/adframe",
  "||/adiframe",
  "||/adview",
  "||/adclick",
  "||/adimg",
  "||/adbanner",
  "||/advertisement",
  "||/sponsored",
  "||/prebid",
  "||/pubads",
  "||/securepubads",
  "||/gpt.js",
  "||/gpt/",
];

function fetchText(url) {
  return new Promise((resolve, reject) => {
    const lib = url.startsWith("https") ? https : http;
    lib
      .get(url, { headers: { "User-Agent": "WebShield-RuleGenerator/2.2" } }, (res) => {
        if (res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
          fetchText(res.headers.location).then(resolve).catch(reject);
          return;
        }
        if (res.statusCode !== 200) {
          reject(new Error(`HTTP ${res.statusCode} for ${url}`));
          return;
        }
        let data = "";
        res.on("data", (chunk) => (data += chunk));
        res.on("end", () => resolve(data));
      })
      .on("error", reject);
  });
}

function isValidUrlFilter(filter) {
  if (!filter || filter.length > 4096) return false;
  if (filter.includes("#")) return false;
  if (/[\x00-\x1f]/.test(filter)) return false;
  return true;
}

function parseFilterLine(line) {
  line = line.trim();
  if (!line || line.startsWith("!") || line.startsWith("[")) return null;
  if (line.startsWith("@@")) return null; // exception
  if (line.includes("##") || line.includes("#@#") || line.includes("#?#")) return null;
  if (line.includes("$") && !line.startsWith("||")) {
    // element hiding or option rules — skip unless domain anchor present
    const anchor = line.indexOf("||");
    if (anchor === -1) return null;
    line = line.slice(anchor);
  }

  // Domain-only: ||example.com^
  if (/^\|\|[^\s/|^]+\^$/.test(line)) {
    return { filter: line, type: "domain" };
  }

  // Domain with path: ||example.com/path^ or ||example.com/path
  if (line.startsWith("||")) {
    let filter = line.split("$")[0].trim();
    if (filter.length < 4) return null;
    if (!filter.endsWith("^") && !filter.endsWith("*")) {
      filter += "^";
    }
    return { filter, type: "url" };
  }

  // Path-only patterns useful for DNR
  if (
    /^\*?\/(ads|ad|advert|banner|popup|popunder|interstitial|analytics|tracking|tracker|beacon|pagead|pubads|prebid|gpt)/i.test(
      line,
    )
  ) {
    let filter = line.split("$")[0].trim();
    return { filter, type: "path" };
  }

  return null;
}

function extractRulesFromText(text, priority) {
  const rules = new Map();
  for (const rawLine of text.split("\n")) {
    const parsed = parseFilterLine(rawLine);
    if (!parsed || !isValidUrlFilter(parsed.filter)) continue;
    if (!rules.has(parsed.filter)) {
      rules.set(parsed.filter, priority);
    }
  }
  return rules;
}

function makeRule(id, urlFilter, priority) {
  return {
    id,
    priority,
    action: { type: "block" },
    condition: {
      urlFilter,
      resourceTypes: RESOURCE_TYPES,
    },
  };
}

async function main() {
  console.log("WebShield.AI — Generating DNR rules...\n");

  const allFilters = new Map();

  // Explicit high-priority patterns first
  for (const pattern of EXPLICIT_PATTERNS) {
    if (isValidUrlFilter(pattern)) {
      allFilters.set(pattern, 10);
    }
  }
  console.log(`Explicit patterns: ${EXPLICIT_PATTERNS.length}`);

  for (const list of FILTER_LISTS) {
    try {
      console.log(`Fetching ${list.name}...`);
      const text = await fetchText(list.url);
      const parsed = extractRulesFromText(text, list.priority);
      let added = 0;
      for (const [filter, priority] of parsed) {
        if (!allFilters.has(filter)) {
          allFilters.set(filter, priority);
          added++;
        }
      }
      console.log(`  +${added} new rules (${parsed.size} parsed)`);
    } catch (err) {
      console.warn(`  Skipped ${list.name}: ${err.message}`);
    }
  }

  // Sort: higher priority first, then domain rules before path rules
  const sorted = [...allFilters.entries()].sort((a, b) => {
    if (b[1] !== a[1]) return b[1] - a[1];
    const aDomain = a[0].startsWith("||") && !a[0].includes("/");
    const bDomain = b[0].startsWith("||") && !b[0].includes("/");
    if (aDomain && !bDomain) return -1;
    if (!aDomain && bDomain) return 1;
    return a[0].localeCompare(b[0]);
  });

  const capped = sorted.slice(0, MAX_RULES);
  const rules = capped.map(([urlFilter, priority], index) =>
    makeRule(index + 1, urlFilter, priority),
  );

  fs.writeFileSync(OUTPUT, JSON.stringify(rules, null, 2));
  const sizeKB = Math.round(fs.statSync(OUTPUT).size / 1024);
  console.log(`\nGenerated ${rules.length} rules → ${OUTPUT} (${sizeKB} KB)`);

  // Platform rules (YouTube, Twitch, Social)
  try {
    const platformRules = require("./rules-platform-data.js");
    fs.writeFileSync(OUTPUT_PLATFORM, JSON.stringify(platformRules, null, 2));
    console.log(`Generated ${platformRules.length} platform rules → ${OUTPUT_PLATFORM}`);
  } catch (err) {
    console.warn("Platform rules skipped:", err.message);
  }

  // Security rules (miners, fingerprinting) — keep bundled file if present
  if (fs.existsSync(OUTPUT_SECURITY)) {
    const sec = JSON.parse(fs.readFileSync(OUTPUT_SECURITY, "utf8"));
    console.log(`Security rules: ${sec.length} (unchanged) → ${OUTPUT_SECURITY}`);
  }
}

main().catch((err) => {
  console.error("Fatal:", err);
  process.exit(1);
});
