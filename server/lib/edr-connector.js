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

module.exports = { acknowledgeAlert, addComment, createSuppressionRule };
