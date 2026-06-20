/**
 * WebShield.AI — Unit Tests
 * Run: npm test
 */

const { describe, it } = require("node:test");
const assert = require("node:assert/strict");
const {
  classifyRequest, isThirdParty, isScamDomain, optimizeRules, extractHostname,
} = require("../lib/webshield-utils");

describe("extractHostname", () => {
  it("parses valid URLs", () => {
    assert.equal(extractHostname("https://ads.example.com/track"), "ads.example.com");
  });
  it("returns empty for invalid URLs", () => {
    assert.equal(extractHostname("not-a-url"), "");
  });
});

describe("isThirdParty", () => {
  it("detects third-party requests", () => {
    assert.equal(
      isThirdParty("https://doubleclick.net/ads", "https://example.com/page"),
      true,
    );
  });
  it("detects first-party requests", () => {
    assert.equal(
      isThirdParty("https://example.com/static/app.js", "https://example.com/page"),
      false,
    );
  });
  it("treats subdomains as first-party", () => {
    assert.equal(
      isThirdParty("https://cdn.example.com/app.js", "https://example.com/page"),
      false,
    );
  });
});

describe("classifyRequest", () => {
  it("classifies ad URLs", () => {
    const r = classifyRequest("https://pagead2.googlesyndication.com/pagead/js");
    assert.equal(r.category, "ad");
    assert.equal(r.isAd, true);
  });
  it("classifies tracker URLs", () => {
    const r = classifyRequest("https://www.google-analytics.com/collect?v=1");
    assert.equal(r.category, "tracker");
    assert.equal(r.isTracker, true);
  });
  it("classifies miner URLs", () => {
    const r = classifyRequest("https://coinhive.com/lib/miner.min.js");
    assert.equal(r.category, "miner");
    assert.equal(r.isAd, true);
  });
  it("classifies fingerprint URLs", () => {
    const r = classifyRequest("https://cdn.fpjs.io/v3/fp.js");
    assert.equal(r.category, "fingerprint");
    assert.equal(r.isTracker, true);
  });
  it("returns unknown for clean URLs", () => {
    const r = classifyRequest("https://cdn.jsdelivr.net/npm/vue@3");
    assert.equal(r.category, "unknown");
    assert.equal(r.isAd, false);
  });
});

describe("isScamDomain", () => {
  it("flags phishing-style domains", () => {
    assert.equal(isScamDomain("paypal-login-verify.xyz"), true);
  });
  it("allows normal domains", () => {
    assert.equal(isScamDomain("github.com"), false);
  });
});

describe("optimizeRules", () => {
  it("removes duplicate filters keeping highest priority", () => {
    const rules = [
      { id: 1, filter: "||ads.com^", priority: 5 },
      { id: 2, filter: "||ads.com^", priority: 10 },
      { id: 3, filter: "||track.com^", priority: 8 },
    ];
    const optimized = optimizeRules(rules);
    assert.equal(optimized.length, 2);
    assert.ok(optimized.find((r) => r.id === 2));
    assert.ok(optimized.find((r) => r.id === 3));
  });
});
