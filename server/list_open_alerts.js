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
  // Wide date net (Sept 1 onward) so we don't miss anything the UI is
  // counting. We list, we don't act -- just an inventory.
  const filter = encodeURIComponent(JSON.stringify({
    where: { createdOn: { gte: "2026-09-01T00:00:00.000Z" } },
    order: "createdOn DESC",
    limit: 500
  }));
  const result = await edrRequest("GET", `/api/AlertDetails?filter=${filter}`);
  if (result.status !== 200) { console.error("Fetch failed:", result.status, result.body); return; }
  const allRaws = JSON.parse(result.body);

  const raws = allRaws.filter(r => {
    const ra = r.data?.ruleActions;
    if (ra && typeof ra.alert === "boolean") return ra.alert === true;
    return true;
  });

  console.log(`Total fetched: ${allRaws.length}, real alerts: ${raws.length}\n`);
  for (const r of raws) {
    console.log(`${r.id}  [${r.severity || "?"}]  ${r.name}  (${r.hostname})  ${r.createdOn}`);
  }
})();
