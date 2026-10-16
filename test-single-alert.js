require("dotenv").config();
const https = require("https");
const { acknowledgeAlert, addComment } = require("./server/lib/edr-connector");
const EDR_HOST = "thelau9220.infocyte.com";
const EDR_TOKEN = process.env.DATTO_EDR_TOKEN;
const TARGET_ID = "fce2d849-fcf6-4ca2-97e0-ee8c82fb18e4";

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

async function fetchOne() {
  const filter = encodeURIComponent(JSON.stringify({ where: { id: TARGET_ID } }));
  const result = await edrRequest("GET", `/api/AlertDetails?filter=${filter}`);
  return JSON.parse(result.body)[0];
}

(async () => {
  console.log("=== BEFORE ===");
  const before = await fetchOne();
  console.log(JSON.stringify(before, null, 2));

  console.log("\n=== TAKING ACTION ===");
  await addComment(TARGET_ID, "[SENTINEL TEST] mv used to clear logs, notMalicious=true, testing write-back path.");
  await acknowledgeAlert(TARGET_ID);

  console.log("\n=== AFTER ===");
  const after = await fetchOne();
  console.log(JSON.stringify(after, null, 2));
})();

