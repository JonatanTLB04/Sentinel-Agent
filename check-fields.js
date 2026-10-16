require("dotenv").config();
const https = require("https");
const EDR_HOST = "thelau9220.infocyte.com";
const EDR_TOKEN = process.env.DATTO_EDR_TOKEN;

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
  const openWhere = encodeURIComponent(JSON.stringify({ hostname: "debian-kay", createdOn: { gte: "2026-09-01T00:00:00.000Z" } }));
  const openResult = await edrRequest("GET", `/api/AlertDetails?where=${openWhere}`);
  const openAlerts = JSON.parse(openResult.body);
  console.log("=== KNOWN OPEN (debian-kay, Sept 1+) ===");
  console.log(JSON.stringify(openAlerts[0], null, 2));

  const oldWhere = encodeURIComponent(JSON.stringify({ createdOn: { lt: "2026-08-01T00:00:00.000Z" } }));
  const oldResult = await edrRequest("GET", `/api/AlertDetails?where=${oldWhere}`);
  const oldAlerts = JSON.parse(oldResult.body);
  console.log("=== OLD / LIKELY CLEARED ===");
  console.log(JSON.stringify(oldAlerts[0], null, 2));
})();
