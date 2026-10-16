/**
 * Enriched review for "Initial Attack Pattern" (correlation) alerts and their
 * accompanying curl/process events that plain triageAlert() can't confidently
 * judge on its own, because the top-level correlation record only contains a
 * generic description -- not the child events (parent process, actual command
 * line) that a human reviewer would open the Timeline to see.
 *
 * This script:
 *   1. Fetches each named alert's full record (including its `alerts: [...]`
 *      child-event ID array, present on correlation-type records).
 *   2. Fetches each child event's own full detail.
 *   3. Sends the *combined* detail (parent + every child) to Claude with a
 *      prompt that states the specific known-benign pattern already verified
 *      on this host on 2026-08-13 (Codex CLI zsh/security proxy+keyring
 *      false positive), and asks for a real decision -- not a placeholder.
 *   4. Only auto-resolves if Claude is highly confident this is the SAME
 *      already-verified pattern. Anything else (new process, unfamiliar
 *      domain, ambiguous) stays open with a comment explaining exactly why.
 *
 * Usage:
 *   node server\resolve_correlation_alerts.js --dry <alertId1> <alertId2> ...
 *   node server\resolve_correlation_alerts.js <alertId1> <alertId2> ...
 */
require("dotenv").config();
const https = require("https");
const Anthropic = require("@anthropic-ai/sdk");
const { acknowledgeAlert, addComment } = require("./lib/edr-connector");

const EDR_HOST = "thelau9220.infocyte.com";
const EDR_TOKEN = process.env.DATTO_EDR_TOKEN;
const DRY_RUN = process.argv.includes("--dry");
const ALERT_IDS = process.argv.slice(2).filter(a => a !== "--dry");

const anthropic = new Anthropic({ apiKey: process.env.ANTHROPIC_API_KEY });

if (ALERT_IDS.length === 0) {
  console.error("Usage: node resolve_correlation_alerts.js [--dry] <alertId1> <alertId2> ...");
  process.exit(1);
}

function edrRequest(method, path) {
  return new Promise((resolve, reject) => {
    const options = { hostname: EDR_HOST, port: 443, path, method,
      headers: { "authorization": EDR_TOKEN, "content-type": "application/json" } };
    const req = https.request(options, (res) => {
      let data = "";
      res.on("data", (c) => { data += c; });
      res.on("end", () => resolve({ status: res.statusCode, body: data }));
    });
    req.on("error", reject);
    req.end();
  });
}

async function getAlertDetail(id) {
  const result = await edrRequest("GET", `/api/AlertDetails/${id}`);
  if (result.status !== 200) throw new Error(`Fetch failed for ${id}: ${result.status} ${result.body}`);
  return JSON.parse(result.body);
}

const KNOWN_BENIGN_PATTERN = `
On host KaiBook-Pro.local, on 2026-08-13, a human security reviewer manually
verified (via Datto EDR's Timeline view + full event detail) that "Initial
Attack Pattern" correlation alerts on this host were repeatedly triggered by
TWO specific, confirmed-benign process chains:

1. "zsh" process flagged for "Linux Proxy usage" (T1090) -- caused by Codex
   CLI (parent process: codex-aarch64-apple-darwin) restoring shell state
   between AI-assisted coding commands, referencing proxy env var NAMES
   (HTTP_PROXY, ALL_PROXY) without any real proxy/C2 traffic. Confirmed:
   malicious=false, threatScore=0, signed by Apple Inc.

2. "security" process flagged for "Suspicious Keyring Activity" (T1555.001)
   -- caused by GitHub CLI (parent process: gh) reading its OWN GitHub auth
   token from macOS Keychain via 'security find-generic-password -s
   gh:github.com'. Confirmed: malicious=false, whitelist=true, threatScore=0,
   signed by Apple Inc.

A THIRD process, "chmod" (File Marked Executable, T1059.004), marking git
hook scripts executable during normal development work, was also confirmed
benign in this same investigation.

Suppression rules already exist for these three exact patterns. Any new
correlation alert composed ONLY of these three known event types, on this
same host, can be confidently resolved the same way.

Anything DIFFERENT -- an unfamiliar process, a real network destination that
isn't macOS Keychain/proxy-env-var noise, an actual file upload/download to
an external or suspicious host, or any process not in this list -- must NOT
be assumed benign. Flag it for human review instead, and say specifically
what's different from the known pattern.
`.trim();

async function reviewCorrelationAlert(alertId) {
  const parent = await getAlertDetail(alertId);
  const childIds = parent.data?.alerts || parent.alerts || [];
  const children = [];
  for (const childId of childIds) {
    try {
      children.push(await getAlertDetail(childId));
    } catch (e) {
      children.push({ id: childId, fetchError: e.message });
    }
  }

  const summary = `
PARENT ALERT:
${JSON.stringify({ id: parent.id, name: parent.name, description: parent.data?.description || parent.description, severity: parent.severity, hostname: parent.hostname }, null, 2)}

CHILD EVENTS (${children.length}):
${children.map((c, i) => `--- Child ${i + 1} ---\n${JSON.stringify(c, null, 2)}`).join("\n")}
`.trim();

  const response = await anthropic.messages.create({
    model: "claude-sonnet-4-6",
    max_tokens: 500,
    system: `You are a SOC analyst reviewing a Datto EDR correlation alert. You have one job: decide, with the SAME rigor a careful human analyst would use, whether this alert matches an already-verified benign pattern, or whether it needs human review. Never guess in favor of closing when unsure -- a missed real intrusion is far worse than one extra alert staying open for a human to glance at.

${KNOWN_BENIGN_PATTERN}

Respond with ONLY a JSON object: {"decision": "auto_resolve" | "needs_human_review", "reason": "<one or two sentences, specific, citing exactly which child events matched or didn't match the known pattern>"}`,
    messages: [{ role: "user", content: summary }],
  });

  const raw = response.content.filter(b => b.type === "text").map(b => b.text).join("").trim();
  const cleaned = raw.startsWith("```") ? raw.replace(/```json?/g, "").trim() : raw;
  return { alertId, parent, decision: JSON.parse(cleaned) };
}

(async () => {
  for (const alertId of ALERT_IDS) {
    try {
      const { parent, decision } = await reviewCorrelationAlert(alertId);
      console.log(`\n[${decision.decision}] ${parent.name} (${parent.hostname}) [${alertId}]`);
      console.log(`  Reason: ${decision.reason}`);

      if (DRY_RUN) continue;

      if (decision.decision === "auto_resolve") {
        await addComment(alertId, `[SENTINEL AUTO-RESOLVED - CHILD EVENT REVIEW] ${decision.reason}`);
        await acknowledgeAlert(alertId);
        console.log("  -> Acknowledged.");
      } else {
        await addComment(alertId, `[SENTINEL REVIEW NEEDED - CHILD EVENT REVIEW] ${decision.reason}`);
        console.log("  -> Left open, comment added.");
      }
    } catch (e) {
      console.error(`Error on ${alertId}:`, e.message);
    }
  }
  console.log("\nDone.");
})();
