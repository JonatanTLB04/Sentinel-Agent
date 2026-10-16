with open("server/routes/webhook.js", encoding="utf-8") as f:
    c = f.read()

old = """  const alert = req.body;
  try {
    const result = await triageAlert(alert);
    notify(alert, result);
    addAlert(alert, result.decision, result.reason);
    if (alert.messageId) {"""

new = """  const alert = req.body;
  try {
    const result = await triageAlert(alert);
    notify(alert, result);
    addAlert(alert, result.decision, result.reason);
    console.log(`[DEBUG] messageId=${JSON.stringify(alert.messageId)} decision=${JSON.stringify(result.decision)} ruleName=${JSON.stringify(alert.ruleName)} parentProcessName=${JSON.stringify(alert.parentProcessName)}`);
    if (alert.messageId) {"""

if old in c:
    c = c.replace(old, new)
    with open("server/routes/webhook.js", "w", encoding="utf-8") as f:
        f.write(c)
    print("Diagnostic log added")
else:
    print("NOT FOUND")
