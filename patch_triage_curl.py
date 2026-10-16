"""
Adds a new deterministic check to triage.js for curl/wget alerts that are
clearly benign: threatScore=0, malicious=false, and the network destination
is a known Microsoft/Azure domain. This auto-resolves them without calling
Claude, and applies to any user on any machine — not just Kaylee.
"""
import shutil

with open("server/lib/triage.js", encoding="utf-8") as f:
    c = f.read()

if "isMicrosoftDestination" in c:
    print("Patch ya aplicado — no se toco nada.")
    raise SystemExit

# Known safe Microsoft/Azure domains for curl uploads (extend as needed)
new_function = '''
// Domains that are always safe destinations for curl/wget activity when
// Datto itself says malicious=false and threatScore=0. These are Microsoft
// and common cloud/dev infrastructure domains used by TLB for deployments,
// package management, and API calls.
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
  // Only applies when Datto itself says it's not malicious
  if (alert.malicious !== false || (alert.threatScore || 0) > 0) return false;

  const ruleName = (alert.ruleName || "").toLowerCase();
  if (!ruleName.includes("curl") && !ruleName.includes("wget")) return false;

  // Check commandLine for known-safe domains
  const cmd = alert.commandLine || "";
  return SAFE_CURL_DESTINATIONS.some((domain) => cmd.includes(domain));
}

'''

old_function_anchor = "function deterministicTriage(alert) {"
new_check = '''function deterministicTriage(alert) {
  // Tier 2a: curl/wget to known-safe Microsoft/cloud destinations
  // with Datto confirming malicious=false and threatScore=0.
  // Applies to any user on any machine.
  if (isSafeCurlDestination(alert)) {
    const dest = SAFE_CURL_DESTINATIONS.find((d) => (alert.commandLine || "").includes(d)) || "known-safe domain";
    return {
      decision: "auto_resolve",
      reason: `curl/wget to known-safe destination (${dest}). Datto confirms malicious=false, threatScore=0. Normal deployment/package-management activity.`,
      tier: 2,
    };
  }
'''

old_tier1_check = "function deterministicTriage(alert) {\n  if (isConfirmedThreat(alert)) {"
new_full = new_check + "  if (isConfirmedThreat(alert)) {"

assert old_function_anchor in c, "deterministicTriage not found"

c = c.replace(old_function_anchor, new_function + new_full, 1)

shutil.copy("server/lib/triage.js", "server/lib/triage.js.bak")
with open("server/lib/triage.js", "w", encoding="utf-8") as f:
    f.write(c)

print("Listo. server/lib/triage.js actualizado (respaldo en triage.js.bak)")
