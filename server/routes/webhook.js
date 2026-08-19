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
  try {
    const result = await triageAlert(alert);
    notify(alert, result);
    addAlert(alert, result.decision, result.reason);
    if (alert.messageId) {
      if (result.decision === "auto_resolve") {
        await addComment(alert.messageId, `[SENTINEL AUTO-RESOLVED] ${result.reason}`);
        await acknowledgeAlert(alert.messageId);
        if (alert.ruleName && alert.parentProcessName) {
          await createSuppressionRule(
            `SENTINEL - ${alert.ruleName} / ${alert.parentProcessName}`,
            `Auto-created by SENTINEL. ${result.reason}`,
            alert.messageId,
            alert.ruleName,
            alert.parentProcessName
          );
        }
      } else if (result.decision === "escalate") {
        await addComment(alert.messageId, `[SENTINEL ESCALATE] ${result.reason}`);
      } else {
        await addComment(alert.messageId, `[SENTINEL REVIEW NEEDED] ${result.reason}`);
      }
    }
    res.status(200).json({ received: true, decision: result.decision });
  } catch (err) {
    console.error("Triage error:", err.message);
    res.status(500).json({ error: "Triage failed" });
  }
});

module.exports = router;
