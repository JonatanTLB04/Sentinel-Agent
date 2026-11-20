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
    postTeams(alert, triageResult);
  }
}

// Optional: post escalations to Teams (Workflows webhook). Best-effort, never throws.
function postTeams(alert, triageResult) {
  const url = process.env.TEAMS_WEBHOOK_URL;
  if (!url || !/^https:\/\//i.test(url)) return;
  try {
    const { redactString } = require("./redact");
    const host = alert.hostname || (alert.hostInfo && alert.hostInfo.hostname) || "unknown host";
    const sev = alert.severity || alert.ruleSeverity || "unknown";
    const rule = alert.ruleName || (alert.data && alert.data.ruleName) || alert.name || "unknown";
    const reason = redactString(String(triageResult.reason || "")).slice(0, 700);
    const card = {
      type: "message",
      attachments: [
        {
          contentType: "application/vnd.microsoft.card.adaptive",
          contentUrl: null,
          content: {
            $schema: "http://adaptivecards.io/schemas/adaptive-card.json",
            type: "AdaptiveCard",
            version: "1.4",
            body: [
              { type: "TextBlock", text: "SENTINEL escalation - needs a human", weight: "Bolder", size: "Medium" },
              {
                type: "FactSet",
                facts: [
                  { title: "Host", value: String(host) },
                  { title: "Severity", value: String(sev) },
                  { title: "Rule", value: String(rule) },
                ],
              },
              { type: "TextBlock", text: reason, wrap: true },
            ],
          },
        },
      ],
    };
    const body = JSON.stringify(card);
    const u = new URL(url);
    const req = require("https").request(
      { hostname: u.hostname, path: u.pathname + u.search, method: "POST", headers: { "content-type": "application/json", "content-length": Buffer.byteLength(body) } },
      (res) => { res.on("data", () => {}); res.on("end", () => {}); }
    );
    req.setTimeout(8000, () => req.destroy());
    req.on("error", (e) => console.error("Teams notify failed:", e.message));
    req.write(body);
    req.end();
  } catch (e) {
    console.error("Teams notify failed:", e.message);
  }
}

module.exports = { notify };
