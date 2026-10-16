"use strict";
const Anthropic = require("@anthropic-ai/sdk");
const client = new Anthropic({ apiKey: process.env.ANTHROPIC_API_KEY });

function isConfirmedThreat(alert) {
  return (
    alert.malicious === true ||
    alert.compromised === true ||
    alert.threatCategory === "Malware"
  );
}

const ALWAYS_ESCALATE_PREFIXES = new Set(["PHISH", "TR", "TROJ", "RANSOM", "WORM"]);

function categoryPrefix(alert) {
  const raw = (alert.avThreatName || alert.threatName || alert.malware || "");
  if (!raw || typeof raw !== "string") return "";
  return raw.split("/")[0].toUpperCase();
}

const KNOWN_BENIGN_PATTERNS = [
  {
    sha256: "ef37663b44ac66920c6f33694deea01acb78ae3f3012884819373fa04c3eb5f0",
    parentProcessName: "claude.exe",
    ruleName: "Exe to Reg Key using Reg.exe",
    note: "Claude Code CLI registering its own claude-cli:// URI protocol handler. Confirmed 2026-07-29 (tlb-trestonf-lt).",
  },
  {
    sha256: "69ff7292c0d081bdf5866bc84dde96d5a14f4a7deafeb9483739be68c48ac2b3",
    parentProcessName: "dash",
    ruleName: "Actions on Sensitive Directories",
    note: "sed parsing PostgreSQL start.conf during normal service startup. Confirmed 2026-07-29 (debian-kay).",
  },
];

function matchesKnownBenignPattern(alert) {
  return KNOWN_BENIGN_PATTERNS.find(
    (p) =>
      p.sha256 === alert.sha256 &&
      p.parentProcessName === alert.parentProcessName &&
      p.ruleName === alert.ruleName
  );
}

const DUAL_USE_PREFIXES = new Set(["PUA"]);
const DUAL_USE_ALLOWLIST = {};
const TRUSTED_PUBLISHERS = new Set(["Microsoft Corporation", "Microsoft Windows"]);

function isTrustedSignature(alert) {
  const subject = alert.signature && alert.signature.subjectName;
  return alert.signed === true && subject && TRUSTED_PUBLISHERS.has(subject);
}


// Known-safe destinations for curl/wget: auto-resolve when Datto confirms
// malicious=false and threatScore=0. Applies to any user, any machine.
const SAFE_CURL_DESTINATIONS = [
  "management.azure.com",
  ".azure.com",
  ".microsoft.com",
  ".windows.net",
  ".azurewebsites.net",
  ".azurefd.net",
  "github.com",
  "api.github.com",
  "raw.githubusercontent.com",
  "analytics.brew.sh",
  "formulae.brew.sh",
  "pypi.org",
  "files.pythonhosted.org",
  "registry.npmjs.org",
];

function isSafeCurlDestination(alert) {
  if (alert.malicious !== false || (alert.threatScore || 0) > 0) return false;
  const ruleName = (alert.ruleName || "").toLowerCase();
  if (!ruleName.includes("curl") && !ruleName.includes("wget")) return false;
  const cmd = alert.commandLine || "";
  return SAFE_CURL_DESTINATIONS.some((d) => cmd.includes(d));
}

function deterministicTriage(alert) {
  // Tier 2a: curl/wget to known-safe destinations
  if (isSafeCurlDestination(alert)) {
    const dest = SAFE_CURL_DESTINATIONS.find((d) => (alert.commandLine || "").includes(d)) || "known-safe domain";
    return {
      decision: "auto_resolve",
      reason: `curl/wget to known-safe destination (${dest}). Datto confirms malicious=false, threatScore=0.`,
      tier: 2,
    };
  }

  if (isConfirmedThreat(alert)) {
    return {
      decision: "escalate",
      reason: `Confirmed threat by Datto detection engine (${alert.avThreatName || alert.malware || "malicious=true"}). Always requires human review.`,
      tier: 1,
    };
  }
  const prefix = categoryPrefix(alert);
  if (prefix && ALWAYS_ESCALATE_PREFIXES.has(prefix)) {
    return {
      decision: "escalate",
      reason: `Category '${prefix}' is content-based malware. Always requires human review.`,
      tier: 1,
    };
  }
  const match = matchesKnownBenignPattern(alert);
  if (match) {
    return {
      decision: "auto_resolve",
      reason: `Matches known-benign pattern: ${match.note}`,
      tier: 2,
    };
  }
  if (prefix && DUAL_USE_PREFIXES.has(prefix)) {
    const approved = DUAL_USE_ALLOWLIST[alert.sha256];
    if (approved) {
      return { decision: "auto_resolve", reason: `Dual-use tool, explicitly allowlisted: ${approved}`, tier: 3 };
    }
    return {
      decision: "escalate",
      reason: `Category '${prefix}' is a dual-use tool. Needs human review.`,
      tier: 3,
    };
  }
  if (isTrustedSignature(alert) && alert.ruleSeverity !== "high") {
    return {
      decision: "auto_resolve",
      reason: `Signed by trusted publisher '${alert.signature.subjectName}', severity is ${alert.ruleSeverity || "unspecified"}.`,
      tier: 4,
    };
  }
  return null;
}

async function claudeTriage(alert) {
  const prompt = `You are a security analyst reviewing a Datto EDR alert. Analyze it and recommend what to do.
Alert data:
${JSON.stringify(alert, null, 2)}
Respond ONLY with this JSON shape, no other text:
{"recommendation": "likely_benign|needs_review|likely_malicious", "reasoning": "2-3 sentences explaining why", "suggested_next_step": "what a human should check next"}`;

  const response = await client.messages.create({
    model: "claude-sonnet-4-6",
    max_tokens: 500,
    messages: [{ role: "user", content: prompt }],
  });

  const text = response.content.find((b) => b.type === "text")?.text || "{}";
  const clean = text.replace(/```json|```/g, "").trim();
  try {
    const parsed = JSON.parse(clean);
    const decision = parsed.recommendation === "likely_benign" ? "auto_resolve" : "needs_human_review";
    return {
      decision,
      recommendation: parsed.recommendation,
      reason: parsed.reasoning,
      suggestedNextStep: parsed.suggested_next_step,
      tier: 5,
    };
  } catch (err) {
    return {
      decision: "needs_human_review",
      recommendation: "needs_review",
      reason: "Could not parse Claude response ? flagging for manual review.",
      suggestedNextStep: "Review Threat Details and Metadata manually.",
      tier: 5,
    };
  }
}

async function triageAlert(alert) {
  const deterministic = deterministicTriage(alert);
  if (deterministic) return deterministic;
  return claudeTriage(alert);
}

module.exports = {
  triageAlert,
  deterministicTriage,
  claudeTriage,
  KNOWN_BENIGN_PATTERNS,
  DUAL_USE_ALLOWLIST,
  TRUSTED_PUBLISHERS,
};
