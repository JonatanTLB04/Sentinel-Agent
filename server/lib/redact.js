"use strict";
// redact.js - remove secrets from anything that leaves SENTINEL (Claude, VirusTotal,
// Teams, logs). EDR alerts routinely carry Bearer tokens, presigned-URL signatures and
// API keys inside the command line, and we never want those copied around.

const HEX_ONLY = /^[a-f0-9]{32,128}$/i; // file hashes are useful evidence: keep them

const PATTERNS = [
  [/(authorization\s*[:=]\s*)(bearer\s+|basic\s+)?[^\s"']+/gi, "$1[REDACTED]"],
  [/(bearer\s+)[A-Za-z0-9\-._~+\/]+=*/gi, "$1[REDACTED]"],
  [/(X-Amz-(?:Security-Token|Signature|Credential)=)[^&\s"']+/gi, "$1[REDACTED]"],
  [
    /([?&](?:token|access_token|id_token|refresh_token|api[_-]?key|apikey|key|sig|signature|password|pwd|passwd|secret|auth|code)=)[^&\s"']+/gi,
    "$1[REDACTED]",
  ],
  [/\bsk-ant-[A-Za-z0-9_\-]+/g, "[REDACTED_KEY]"],
  [/\bsk-[A-Za-z0-9]{20,}/g, "[REDACTED_KEY]"],
  [/\bgh[pousr]_[A-Za-z0-9]{20,}/g, "[REDACTED_KEY]"],
  [/\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}/g, "[REDACTED_JWT]"],
  [/\b(?:AKIA|ASIA)[A-Z0-9]{16}\b/g, "[REDACTED_AWS_KEY]"],
  [/(\s(?:-u|--user)\s+)[^\s"']+/g, "$1[REDACTED]"],
];

// long opaque blobs (base64, session ids). Hex hashes are preserved.
const LONG_BLOB = /[A-Za-z0-9+\/=_\-]{60,}/g;

function redactString(input) {
  if (typeof input !== "string" || input.length === 0) return input;
  let out = input;
  for (const [re, rep] of PATTERNS) out = out.replace(re, rep);
  out = out.replace(LONG_BLOB, (m) => (HEX_ONLY.test(m) ? m : "[REDACTED_LONG]"));
  return out;
}

function redact(value, depth = 0) {
  if (depth > 8) return "[TRUNCATED_DEPTH]";
  if (typeof value === "string") return redactString(value);
  if (Array.isArray(value)) return value.slice(0, 200).map((v) => redact(v, depth + 1));
  if (value && typeof value === "object") {
    const out = {};
    for (const [k, v] of Object.entries(value)) {
      if (/^(password|passwd|pwd|secret|token|apikey|api_key|authorization|cookie)$/i.test(k)) {
        out[k] = "[REDACTED]";
      } else {
        out[k] = redact(v, depth + 1);
      }
    }
    return out;
  }
  return value;
}

// Drop the query string / fragment / credentials from a URL so we can look up the
// destination without ever sending a presigned signature or token anywhere.
function stripUrlSecrets(urlStr) {
  try {
    const u = new URL(urlStr);
    u.username = "";
    u.password = "";
    u.search = "";
    u.hash = "";
    return u.toString();
  } catch (_) {
    return null;
  }
}

module.exports = { redact, redactString, stripUrlSecrets };
