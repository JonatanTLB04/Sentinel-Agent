require("dotenv").config();
const https = require("https");
const { triageAlert } = require("./lib/triage");
const { acknowledgeAlert, addComment, createSuppressionRule } = require("./lib/edr-connector");

const EDR_HOST = "thelau9220.infocyte.com";
const EDR_TOKEN = process.env.DATTO_EDR_TOKEN;
const DASHBOARD_HOST = "sentinel-agent-production-aa41.up.railway.app";
const DRY_RUN = process.argv.includes("--dry");

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

function logToDashboard(alert, decision, reason) {
  return new Promise((resolve) => {
    const bodyStr = JSON.stringify({ alert, decision, reason });
    const options = { hostname: DASHBOARD_HOST, port: 443, path: "/api/alerts/log", method: "POST",
      headers: { "content-type": "application/json", "content-length": Buffer.byteLength(bodyStr) } };
    const req = https.request(options, (res) => { res.on("data", () => {}); res.on("end", resolve); });
    req.on("error", (e) => { console.error("Dashboard log failed:", e.message); resolve(); });
    req.write(bodyStr);
    req.end();
  });
}

(async () => {
  const filter = encodeURIComponent(JSON.stringify({
    where: { archived: false, hostname: { inq: ["debian-kay", "KaiBook-Pro.local"] } },
    order: "createdOn DESC",
    limit: 100
  }));
  const result = await edrRequest("GET", `/api/AlertDetails?filter=${filter}`);
  if (result.status !== 200) { console.error("Fetch failed:", result.status, result.body); return; }
  const allRaws = JSON.parse(result.body);

  const raws = allRaws.filter(r => {
    const ra = r.data?.ruleActions;
    if (ra && typeof ra.alert === "boolean") return ra.alert === true;
    return true;
  });

  console.log(`Fetched ${allRaws.length} total records, ${raws.length} are real alerts.${DRY_RUN ? " [DRY RUN]" : ""}`);

  for (const raw of raws) {
    const normalized = { ...raw.data, ...raw, data: raw.data };
    const messageId = raw.id;
    const decision = await triageAlert(normalized);
    console.log(`[${decision.decision}] ${raw.name} (${raw.hostname}) — ${(decision.reason || "").slice(0, 100)}`);

    if (DRY_RUN) continue;

    const ruleName = normalized.ruleName;
    const parentProcessName = normalized.parentProcessName;

    if (decision.decision === "auto_resolve") {
      await addComment(messageId, `[SENTINEL AUTO-RESOLVED - BACKFILL] ${decision.reason}`);
      await acknowledgeAlert(messageId);
      if (ruleName && parentProcessName) {
        await createSuppressionRule(`SENTINEL - ${ruleName} / ${parentProcessName}`, "Auto-created by SENTINEL backfill.", messageId, ruleName, parentProcessName);
      }
    } else if (decision.decision === "escalate") {
      await addComment(messageId, `[SENTINEL ESCALATE - BACKFILL] ${decision.reason}`);
    } else {
      await addComment(messageId, `[SENTINEL REVIEW NEEDED - BACKFILL] ${decision.reason}`);
    }

    await logToDashboard(normalized, decision.decision, decision.reason);
  }

  console.log("Done.");
})();
