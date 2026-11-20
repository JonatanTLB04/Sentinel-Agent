"use strict";
const https = require("https");

const EDR_HOST = "thelau9220.infocyte.com";
const EDR_TOKEN = process.env.DATTO_EDR_TOKEN;

function edrRequest(method, path, body = null) {
  return new Promise((resolve, reject) => {
    const bodyStr = body ? JSON.stringify(body) : "";
    const options = {
      hostname: EDR_HOST,
      port: 443,
      path,
      method,
      headers: {
        "authorization": EDR_TOKEN,
        "content-type": "application/json",
        "content-length": Buffer.byteLength(bodyStr),
      },
    };
    const req = https.request(options, (res) => {
      let data = "";
      res.on("data", (chunk) => { data += chunk; });
      res.on("end", () => resolve({ status: res.statusCode, body: data }));
    });
    req.on("error", reject);
    if (bodyStr) req.write(bodyStr);
    req.end();
  });
}

async function acknowledgeAlert(messageId) {
  const where = encodeURIComponent(JSON.stringify({ id: messageId }));
  const result = await edrRequest("POST", `/api/alerts/archive?where=${where}`);
  if (result.status === 204) {
    console.log(`✅ Acknowledged alert ${messageId}`);
    return true;
  }
  console.error(`❌ Failed to acknowledge ${messageId}: ${result.status} ${result.body}`);
  return false;
}

async function addComment(messageId, comment) {
  const result = await edrRequest("POST", "/api/userComments", {
    relatedId: messageId,
    value: comment,
  });
  if (result.status === 200) {
    console.log(`💬 Comment added to alert ${messageId}`);
    return true;
  }
  console.error(`❌ Failed to add comment to ${messageId}: ${result.status} ${result.body}`);
  return false;
}

async function createSuppressionRule(name, description, alertId, ruleName, parentProcessName) {
  const metadata = {
    ruleName: { display: "Rule Name", active: true, value: ruleName, dataType: "string", operator: "==" },
    parentProcessName: { display: "Parent Process Name", active: true, value: parentProcessName, dataType: "string", operator: "==" },
  };
  const result = await edrRequest("POST", "/api/suppressionRules", {
    name,
    description,
    alertId,
    organizationId: "",
    locationId: "",
    metadata: JSON.stringify(metadata),
  });
  if (result.status === 200) {
    console.log(`🛡️ Suppression rule created: ${name}`);
    return true;
  }
  console.error(`❌ Failed to create suppression rule: ${result.status} ${result.body}`);
  return false;
}

// ---- read helpers used by the investigator (read-only) ----
function edrGet(path) {
  return new Promise((resolve, reject) => {
    const req = https.request(
      { hostname: EDR_HOST, port: 443, path, method: "GET", headers: { authorization: EDR_TOKEN, "content-type": "application/json" } },
      (res) => {
        let data = "";
        res.on("data", (c) => { data += c; });
        res.on("end", () => resolve({ status: res.statusCode, body: data }));
      }
    );
    req.setTimeout(15000, () => req.destroy(new Error("EDR request timed out")));
    req.on("error", reject);
    req.end();
  });
}

async function getAlertDetail(id) {
  const r = await edrGet(`/api/AlertDetails/${encodeURIComponent(id)}`);
  if (r.status !== 200) throw new Error(`EDR HTTP ${r.status}`);
  return JSON.parse(r.body);
}

async function listAlertsByHost(hostname, days = 7) {
  const since = new Date(Date.now() - days * 86400000).toISOString();
  const filter = encodeURIComponent(JSON.stringify({ where: { hostname, createdOn: { gte: since } }, order: "createdOn DESC", limit: 50 }));
  const r = await edrGet(`/api/AlertDetails?filter=${filter}`);
  if (r.status !== 200) throw new Error(`EDR HTTP ${r.status}`);
  return JSON.parse(r.body).filter((x) => {
    const ra = x.data && x.data.ruleActions;
    return !(ra && typeof ra.alert === "boolean") || ra.alert === true;
  });
}

module.exports = { acknowledgeAlert, addComment, createSuppressionRule, getAlertDetail, listAlertsByHost };
