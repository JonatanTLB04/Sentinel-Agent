const express = require("express");
const router = express.Router();
const { triageAlert } = require("../lib/triage");
const { notify } = require("../lib/notifier");
const { acknowledgeAlert, addComment, createSuppressionRule } = require("../lib/edr-connector");
const { addAlert } = require("../lib/store");

router.post("/edr", async (req, res) => {
  const secret = req.headers["x-sentinel-secret"];
  if (secret !== process.env.EDR_WEBHOOK_SECRET) {
    return res.status(401).json({ error: "Invalid secret" });
  }
  const alert = req.body;
  console.log("RAW ALERT PAYLOAD:", JSON.stringify(alert, null, 2));
  try {
    const result = await triageAlert(alert);
    notify(alert, result);
    addAlert(alert, result.decision, result.reason);
    const messageId = alert.messageId || alert.id || alert.threatId || alert.detectionId || alert.itemId || alert.uid;
    const ruleName = alert.ruleName || alert.flagName || alert.detectionName;
    const parentProcessName = alert.parentProcessName || alert.processName || alert.grandParentProcessName;
    console.log(`[DEBUG] messageId=${JSON.stringify(messageId)} decision=${JSON.stringify(result.decision)} ruleName=${JSON.stringify(ruleName)} parentProcessName=${JSON.stringify(parentProcessName)}`);
    if (messageId) {
      if (result.decision === "auto_resolve") {
        await addComment(messageId, `[SENTINEL AUTO-RESOLVED] ${result.reason}`);
        await acknowledgeAlert(messageId);
        if (ruleName && parentProcessName) {
          await createSuppressionRule(
            `SENTINEL - ${ruleName} / ${parentProcessName}`,
            `Auto-created by SENTINEL. ${result.reason}`,
            messageId,
            ruleName,
            parentProcessName
          );
        }
      } else if (result.decision === "escalate") {
        await addComment(messageId, `[SENTINEL ESCALATE] ${result.reason}`);
      } else {
        await addComment(messageId, `[SENTINEL REVIEW NEEDED] ${result.reason}`);
      }
    }
    res.status(200).json({ received: true, decision: result.decision });
  } catch (err) {
    console.error("Triage error:", err.message);
    res.status(500).json({ error: "Triage failed" });
  }
});

module.exports = router;
