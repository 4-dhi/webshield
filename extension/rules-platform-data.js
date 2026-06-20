#!/usr/bin/env node
/**
 * WebShield.AI — Platform-specific DNR rules (YouTube, Twitch, Social)
 * Generated subset; run `node generate-rules.js` for full regeneration.
 */

const rules = [
  // YouTube
  { id: 1, priority: 20, action: { type: "block" }, condition: { urlFilter: "||googlevideo.com/videoplayback", resourceTypes: ["media", "xmlhttprequest"] } },
  { id: 2, priority: 20, action: { type: "block" }, condition: { urlFilter: "||youtube.com/api/stats/ads", resourceTypes: ["xmlhttprequest", "ping", "other"] } },
  { id: 3, priority: 20, action: { type: "block" }, condition: { urlFilter: "||youtube.com/get_midroll_info", resourceTypes: ["xmlhttprequest"] } },
  { id: 4, priority: 20, action: { type: "block" }, condition: { urlFilter: "||youtube.com/ptracking", resourceTypes: ["xmlhttprequest", "ping"] } },
  { id: 5, priority: 20, action: { type: "block" }, condition: { urlFilter: "||www.youtube.com/pagead/", resourceTypes: ["script", "xmlhttprequest", "image", "other"] } },
  { id: 6, priority: 20, action: { type: "block" }, condition: { urlFilter: "||static.doubleclick.net/instream/ad_status.js", resourceTypes: ["script"] } },
  { id: 7, priority: 20, action: { type: "block" }, condition: { urlFilter: "||imasdk.googleapis.com^", resourceTypes: ["script", "xmlhttprequest", "media"] } },
  // Twitch
  { id: 10, priority: 18, action: { type: "block" }, condition: { urlFilter: "||amazon-adsystem.com^", resourceTypes: ["script", "image", "xmlhttprequest", "media", "other"] } },
  { id: 11, priority: 18, action: { type: "block" }, condition: { urlFilter: "||twitch.tv/ads^", resourceTypes: ["xmlhttprequest", "script", "other"] } },
  { id: 12, priority: 18, action: { type: "block" }, condition: { urlFilter: "||twitchcdn.net^", resourceTypes: ["script", "xmlhttprequest", "media"] } },
  // Facebook / Instagram
  { id: 20, priority: 16, action: { type: "block" }, condition: { urlFilter: "||facebook.com/tr^", resourceTypes: ["xmlhttprequest", "image", "ping", "other"] } },
  { id: 21, priority: 16, action: { type: "block" }, condition: { urlFilter: "||connect.facebook.net/en_US/fbevents.js", resourceTypes: ["script"] } },
  { id: 22, priority: 16, action: { type: "block" }, condition: { urlFilter: "||pixel.facebook.com^", resourceTypes: ["image", "xmlhttprequest", "ping"] } },
  // Twitter/X
  { id: 30, priority: 16, action: { type: "block" }, condition: { urlFilter: "||static.ads-twitter.com^", resourceTypes: ["script", "image", "xmlhttprequest"] } },
  { id: 31, priority: 16, action: { type: "block" }, condition: { urlFilter: "||ads-api.twitter.com^", resourceTypes: ["xmlhttprequest", "other"] } },
  // Reddit
  { id: 40, priority: 16, action: { type: "block" }, condition: { urlFilter: "||reddit.com/api/v1/ads^", resourceTypes: ["xmlhttprequest"] } },
  { id: 41, priority: 16, action: { type: "block" }, condition: { urlFilter: "||events.reddit.com^", resourceTypes: ["xmlhttprequest", "ping"] } },
  // LinkedIn
  { id: 50, priority: 16, action: { type: "block" }, condition: { urlFilter: "||ads.linkedin.com^", resourceTypes: ["script", "xmlhttprequest", "image"] } },
  { id: 51, priority: 16, action: { type: "block" }, condition: { urlFilter: "||snap.licdn.com^", resourceTypes: ["script", "image", "xmlhttprequest"] } },
  // Popunder / redirect
  { id: 60, priority: 19, action: { type: "block" }, condition: { urlFilter: "||popads.net^", resourceTypes: ["script", "xmlhttprequest", "sub_frame", "other"] } },
  { id: 61, priority: 19, action: { type: "block" }, condition: { urlFilter: "||popcash.net^", resourceTypes: ["script", "xmlhttprequest", "sub_frame", "other"] } },
  { id: 62, priority: 19, action: { type: "block" }, condition: { urlFilter: "||propellerads.com^", resourceTypes: ["script", "xmlhttprequest", "sub_frame", "other"] } },
  // Anti-adblock
  { id: 70, priority: 17, action: { type: "block" }, condition: { urlFilter: "||blockadblock.com^", resourceTypes: ["script"] } },
  { id: 71, priority: 17, action: { type: "block" }, condition: { urlFilter: "||antiadblocksystems.com^", resourceTypes: ["script"] } },
  // Cookie consent spam
  { id: 80, priority: 12, action: { type: "block" }, condition: { urlFilter: "||cdn.cookielaw.org^", resourceTypes: ["script", "xmlhttprequest"] } },
  { id: 81, priority: 12, action: { type: "block" }, condition: { urlFilter: "||consent.cookiebot.com^", resourceTypes: ["script", "xmlhttprequest"] } },
  { id: 82, priority: 12, action: { type: "block" }, condition: { urlFilter: "||onetrust.com^", resourceTypes: ["script", "xmlhttprequest"] } },
];

module.exports = rules;
