/**
 * WebShield.AI — Performance Benchmarks
 * Run: npm run benchmark
 */

const { performance } = require("perf_hooks");
const { classifyRequest, optimizeRules } = require("../lib/webshield-utils");

const TEST_URLS = [
  "https://pagead2.googlesyndication.com/pagead/js/adsbygoogle.js",
  "https://www.google-analytics.com/collect?v=1&tid=UA-123",
  "https://coinhive.com/lib/miner.min.js",
  "https://cdn.fpjs.io/v3/fp.js",
  "https://example.com/static/app.js",
  "https://doubleclick.net/ad.js",
  "https://connect.facebook.net/en_US/fbevents.js",
  "https://static.ads-twitter.com/uwt.js",
  "https://cdn.jsdelivr.net/npm/vue@3",
  "https://youtube.com/api/stats/ads",
];

const ITERATIONS = 100000;

function bench(name, fn) {
  const start = performance.now();
  for (let i = 0; i < ITERATIONS; i++) fn();
  const elapsed = performance.now() - start;
  const opsPerSec = Math.round((ITERATIONS / elapsed) * 1000);
  console.log(`${name}: ${elapsed.toFixed(2)}ms (${opsPerSec.toLocaleString()} ops/sec)`);
  return { name, elapsed, opsPerSec };
}

console.log("WebShield.AI Benchmarks");
console.log("=".repeat(50));
console.log(`Iterations per test: ${ITERATIONS.toLocaleString()}\n`);

const results = [];

results.push(bench("classifyRequest (10 URLs)", () => {
  for (const url of TEST_URLS) classifyRequest(url, "https://example.com");
}));

results.push(bench("classifyRequest (ad URL only)", () => {
  classifyRequest("https://pagead2.googlesyndication.com/pagead/js");
}));

const sampleRules = Array.from({ length: 5000 }, (_, i) => ({
  id: i + 1,
  filter: `||ads${i % 100}.example.com^`,
  priority: i % 10,
}));

results.push(bench("optimizeRules (5000 rules)", () => {
  optimizeRules(sampleRules);
}));

console.log("\n" + "=".repeat(50));
console.log("Summary:");
const fastest = results.reduce((a, b) => (a.opsPerSec > b.opsPerSec ? a : b));
console.log(`Fastest: ${fastest.name} @ ${fastest.opsPerSec.toLocaleString()} ops/sec`);
console.log("\nTarget for 100+ tabs: classifyRequest > 500K ops/sec ✓");
