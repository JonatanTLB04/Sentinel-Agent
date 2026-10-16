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
  const filter = encodeURIComponent(JSON.stringify({
    where: { hostname: "debian-kay" },
    order: "createdOn DESC",
    limit: 5
  }));
  const result = await edrRequest("GET", `/api/AlertDetails?filter=${filter}`);
  console.log("STATUS:", result.status);
  const alerts = JSON.parse(result.body);
  console.log("Count:", Array.isArray(alerts) ? alerts.length : "not an array");
  console.log(JSON.stringify(alerts, null, 2).slice(0, 3000));
})();
