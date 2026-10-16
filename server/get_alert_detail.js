require("dotenv").config();
const https = require("https");
const EDR_HOST = "thelau9220.infocyte.com";
const EDR_TOKEN = process.env.DATTO_EDR_TOKEN;
const ALERT_ID = process.argv[2];

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

(async () => {
  const result = await edrRequest("GET", `/api/AlertDetails/${ALERT_ID}`);
  const parsed = JSON.parse(result.body);
  // Print only the fields that matter for triage
  const d = parsed.data || parsed;
  console.log(JSON.stringify({
    name: parsed.name,
    hostname: parsed.hostname,
    severity: parsed.severity,
    ruleName: d.ruleName,
    processName: d.processName,
    parentProcessName: d.parentProcessName,
    commandLine: d.commandLine,
    networkDestination: d.networkDestination || d.domain || d.url,
    threatScore: d.threatScore,
    malicious: d.malicious,
    signed: d.signed,
  }, null, 2));
})();
