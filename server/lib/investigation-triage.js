"use strict";
// investigation-triage.js - turns an investigation into a triage decision.
//
// Modes (env SENTINEL_INVESTIGATOR_MODE):
//   observe (default) - investigates and records what it WOULD do, closes NOTHING
//   active            - may auto-close Low/Medium alerts that pass every guardrail
//   legacy            - old single-shot Claude triage (not recommended; no guardrails)

const crypto = require("crypto");
const { investigate: realInvestigate } = require("./investigator");
const { evaluateAutoClose, normalizeSeverity, CLOSABLE_SEVERITIES, pick } = require("./guardrails");
const { redactString } = require("./redact");

const CACHE_TTL_MS = 15 * 60 * 1000;
const cache = new Map();
let windowStart = Date.now();
let windowCount = 0;
let running = 0;
const waiters = [];

function maxPerHour() {
  const n = parseInt(process.env.SENTINEL_MAX_INVESTIGATIONS_PER_HOUR || "60", 10);
  return Number.isFinite(n) && n > 0 ? n : 60;
}
function maxConcurrent() {
  const n = parseInt(process.env.SENTINEL_MAX_CONCURRENT_INVESTIGATIONS || "2", 10);
  return Number.isFinite(n) && n > 0 ? n : 2;
}

function budgetAvailable(now) {
  if (now - windowStart > 3600000) {
    windowStart = now;
    windowCount = 0;
  }
  if (windowCount >= maxPerHour()) return false;
  windowCount++;
  return true;
}

async function acquire() {
  if (running < maxConcurrent()) {
    running++;
    return;
  }
  await new Promise((resolve) => waiters.push(resolve));
  running++;
}
function release() {
  running--;
  const next = waiters.shift();
  if (next) next();
}

function cacheKey(alert) {
  const host = (alert.hostInfo && alert.hostInfo.hostname) || pick(alert, "hostname") || "";
  const raw = [pick(alert, "ruleName"), pick(alert, "parentProcessName"), pick(alert, "processName"), host, redactString(String(pick(alert, "commandLine") || ""))].join("|");
  return crypto.createHash("sha256").update(raw).digest("hex");
}

function describe(inv) {
  const ev = (inv.evidence || []).slice(0, 3).map((e) => `${e.source}: ${e.finding}`).join(" | ");
  return `${inv.verdict}/${inv.confidence}. ${inv.summary}${ev ? ` Evidence: ${ev}` : ""}`;
}

function clip(s, n = 900) {
  return s.length > n ? s.slice(0, n - 1) + "…" : s;
}

async function investigativeTriage(alert, mode = "observe", deps = {}) {
  const investigate = deps.investigate || realInvestigate;
  const now = deps.now ? deps.now() : Date.now();
  const sev = normalizeSeverity(alert);
  const investigateHigh = String(process.env.SENTINEL_INVESTIGATE_HIGH || "true").toLowerCase() !== "false";

  if (!CLOSABLE_SEVERITIES.has(sev) && !investigateHigh) {
    return { decision: "needs_human_review", reason: `[SENTINEL] ${sev || "unknown"}-severity alerts are always reviewed by a human.`, tier: 5 };
  }

  const key = cacheKey(alert);
  let inv;
  const hit = cache.get(key);
  if (hit && now - hit.at < CACHE_TTL_MS) {
    inv = hit.inv;
  } else {
    if (!budgetAvailable(now)) {
      return { decision: "needs_human_review", reason: "[INVESTIGATOR skipped] hourly investigation budget reached; left for human review.", tier: 5 };
    }
    await acquire();
    try {
      inv = await investigate(alert);
    } finally {
      release();
    }
    if (!inv.error) cache.set(key, { at: now, inv });
  }

  const gate = evaluateAutoClose(alert, inv);
  const investigation = {
    verdict: inv.verdict,
    confidence: inv.confidence,
    evidence: inv.evidence,
    toolsUsed: (inv.trace && inv.trace.okTools) || [],
    flags: (inv.trace && inv.trace.flags) || [],
    blockers: gate.blockers,
    mode,
  };

  if (inv.verdict === "malicious" || inv.verdict === "suspicious") {
    return {
      decision: "escalate",
      reason: clip(`[INVESTIGATOR ${inv.verdict.toUpperCase()}] ${describe(inv)}${inv.recommended_action ? ` Next: ${inv.recommended_action}` : ""}`),
      tier: 5,
      investigation,
    };
  }

  if (gate.allowed) {
    if (mode === "active") {
      return {
        decision: "auto_resolve",
        reason: clip(`[INVESTIGATOR] Verified benign. ${describe(inv)}`),
        tier: 5,
        allowSuppression: false, // AI decisions never create blanket suppression rules
        investigation,
      };
    }
    return {
      decision: "needs_human_review",
      reason: clip(`[OBSERVE MODE - would auto-resolve] ${describe(inv)}`),
      tier: 5,
      wouldAutoResolve: true,
      investigation,
    };
  }

  return {
    decision: "needs_human_review",
    reason: clip(`[INVESTIGATOR ${inv.verdict}/${inv.confidence}] ${inv.summary} Not auto-closed: ${gate.blockers.join("; ")}.`),
    tier: 5,
    investigation,
  };
}

function _resetForTests() {
  cache.clear();
  windowStart = Date.now();
  windowCount = 0;
  running = 0;
  waiters.length = 0;
}

module.exports = { investigativeTriage, _resetForTests };
