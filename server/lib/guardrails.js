"use strict";
// guardrails.js - hard, deterministic limits on what the AI investigator may do.
// The model only RECOMMENDS. This code decides whether an alert may be auto-closed.
// Alert content is attacker-influenced, so nothing in it (or in the model output) can
// loosen these rules.

const ALWAYS_ESCALATE_PREFIXES = new Set(["PHISH", "TR", "TROJ", "RANSOM", "WORM"]);
const CLOSABLE_SEVERITIES = new Set(["low", "medium"]);

// Datto sends fields at the top level in some payloads and under `data` in others.
function pick(alert, key) {
  if (alert == null) return undefined;
  if (alert[key] !== undefined) return alert[key];
  if (alert.data && alert.data[key] !== undefined) return alert.data[key];
  return undefined;
}

function normalizeSeverity(alert) {
  const raw = pick(alert, "severity") || pick(alert, "ruleSeverity") || "";
  return String(raw).toLowerCase().trim();
}

function categoryPrefix(alert) {
  const raw = pick(alert, "avThreatName") || pick(alert, "threatName") || pick(alert, "malware") || "";
  if (!raw || typeof raw !== "string") return "";
  return raw.split("/")[0].toUpperCase();
}

function isZero(v) {
  return v === 0 || v === "0";
}

// inv = { verdict, confidence, evidence:[{source,finding}], trace:{ okTools:[names], flags:[...] }, error }
function evaluateAutoClose(alert, inv) {
  const blockers = [];

  const sev = normalizeSeverity(alert);
  if (!CLOSABLE_SEVERITIES.has(sev)) blockers.push(`severity '${sev || "unknown"}' is not low/medium`);

  if (pick(alert, "malicious") !== false) blockers.push("Datto did not confirm malicious=false");
  if (!isZero(pick(alert, "threatScore"))) blockers.push("Datto did not confirm threatScore=0");
  if (pick(alert, "compromised") === true) blockers.push("Datto marked the host as compromised");
  if (pick(alert, "threatCategory") === "Malware") blockers.push("Datto threatCategory is Malware");
  if (ALWAYS_ESCALATE_PREFIXES.has(categoryPrefix(alert))) blockers.push("always-escalate malware category");

  if (!inv || inv.error) {
    blockers.push(`investigation did not complete${inv && inv.error ? ` (${inv.error})` : ""}`);
    return { allowed: false, blockers };
  }

  if (inv.verdict !== "benign") blockers.push(`verdict is '${inv.verdict}', not benign`);
  if (inv.confidence !== "high") blockers.push(`confidence is '${inv.confidence}', not high`);

  const okTools = new Set((inv.trace && inv.trace.okTools) || []);
  if (okTools.size < 1) blockers.push("no investigation tool returned usable evidence");

  const evidence = Array.isArray(inv.evidence) ? inv.evidence : [];
  const wellFormed = evidence.filter((e) => e && typeof e.source === "string" && typeof e.finding === "string" && e.finding.trim());
  if (wellFormed.length < 2) blockers.push("fewer than 2 pieces of evidence");
  if (!wellFormed.some((e) => okTools.has(e.source))) {
    blockers.push("no evidence cites a tool that actually ran");
  }

  const flags = (inv.trace && inv.trace.flags) || [];
  for (const f of flags) blockers.push(`red flag from tools: ${f}`);

  return { allowed: blockers.length === 0, blockers };
}

module.exports = { evaluateAutoClose, normalizeSeverity, pick, CLOSABLE_SEVERITIES };
