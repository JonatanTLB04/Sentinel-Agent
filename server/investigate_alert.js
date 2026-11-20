"use strict";
// Try the investigator on ONE real alert. Read-only: it never acknowledges, comments or
// creates rules. Shows what SENTINEL would do in 'active' mode and why.
//   node server/investigate_alert.js <alertId>
require("dotenv").config();
const { getAlertDetail } = require("./lib/edr-connector");
const { investigate } = require("./lib/investigator");
const { evaluateAutoClose } = require("./lib/guardrails");

const id = process.argv[2];
if (!id) {
  console.error("Usage: node server/investigate_alert.js <alertId>");
  process.exit(1);
}
for (const k of ["ANTHROPIC_API_KEY", "DATTO_EDR_TOKEN"]) {
  if (!process.env[k]) {
    console.error(`Missing ${k} in your .env`);
    process.exit(1);
  }
}

(async () => {
  const raw = await getAlertDetail(id);
  const alert = { ...raw.data, ...raw, data: raw.data }; // same normalisation as backfill_current.js
  console.log(`\nAlert: ${raw.name}  host=${raw.hostname}  severity=${raw.severity}  rule=${(raw.data || {}).ruleName}`);
  console.log(`Datto says: malicious=${(raw.data || {}).malicious}  threatScore=${(raw.data || {}).threatScore}`);
  console.log(`VirusTotal key: ${process.env.VIRUSTOTAL_API_KEY ? "configured" : "not configured (DNS/RDAP/page reader only)"}\n`);

  const started = Date.now();
  const inv = await investigate(alert);
  console.log(`VERDICT: ${inv.verdict} (confidence ${inv.confidence})  [${Math.round((Date.now() - started) / 1000)}s, ${inv.trace.steps} model steps]`);
  console.log(`Summary: ${inv.summary}`);
  if (inv.error) console.log(`Error: ${inv.error}`);
  console.log("\nEvidence:");
  for (const e of inv.evidence) console.log(`  - [${e.source}] ${e.finding}`);
  console.log("\nTools called:");
  for (const c of inv.trace.toolCalls) console.log(`  - ${c.name} ${c.ok ? "ok" : "FAILED"} (${c.ms}ms) ${JSON.stringify(c.input).slice(0, 110)}${c.error ? "  error=" + c.error : ""}`);
  if (inv.trace.flags.length) console.log("\nRed flags:\n  - " + inv.trace.flags.join("\n  - "));

  const gate = evaluateAutoClose(alert, inv);
  console.log(`\nGuardrails: ${gate.allowed ? "WOULD AUTO-CLOSE in active mode" : "would NOT auto-close"}`);
  for (const b of gate.blockers) console.log(`  - ${b}`);
  console.log("\nNo action was taken on this alert.");
})().catch((e) => {
  console.error("Failed:", e.message);
  process.exit(1);
});
