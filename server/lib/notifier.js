const fs = require("fs");
const path = require("path");
const LOG_FILE = path.join(__dirname, "..", "..", "alerts.log");

function notify(alert, triageResult) {
  const decision = (triageResult.decision || "unknown").toUpperCase();
  const host = alert.hostname || alert.hostInfo?.hostname || "unknown host";
  const reason = triageResult.reason || triageResult.reasoning || "no reason provided";
  const line = `[${new Date().toISOString()}] ${decision} — ${host} — ${reason}\n`;
  console.log(line.trim());
  fs.appendFileSync(LOG_FILE, line);
  if (triageResult.decision === "escalate") {
    console.log(`🚨 ESCALATE: ${triageResult.reason}`);
  }
}

module.exports = { notify };
