// store.js - In-memory alert store
const alerts = [];
const MAX_ALERTS = 500;

function addAlert(alert, decision, reason) {
  const entry = {
    id: Date.now() + Math.random(),
    timestamp: new Date().toISOString(),
    hostname: alert.hostInfo?.hostname || alert.hostname || "unknown",
    ruleName: alert.ruleName || "Unknown",
    processName: alert.name || "",
    organization: alert.organizationName || "",
    decision,
    reason,
    messageId: alert.messageId || null,
  };
  alerts.unshift(entry);
  if (alerts.length > MAX_ALERTS) alerts.pop();
  return entry;
}

function getAlerts() {
  return alerts;
}

function getStats() {
  const today = new Date().toDateString();
  const todayAlerts = alerts.filter(a => new Date(a.timestamp).toDateString() === today);
  return {
    total: todayAlerts.length,
    auto_resolved: todayAlerts.filter(a => a.decision === "auto_resolve").length,
    escalated: todayAlerts.filter(a => a.decision === "escalate").length,
    review: todayAlerts.filter(a => a.decision === "review").length,
    recent: alerts.slice(0, 20),
  };
}

module.exports = { addAlert, getAlerts, getStats };
