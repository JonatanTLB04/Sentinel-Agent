# SENTINEL Investigator

Claude investigates each unknown alert with tools (host history, DNS, RDAP, VirusTotal, a
restricted page reader) and submits a structured verdict with evidence. **Plain code**
(`guardrails.js`) decides whether that is enough to auto-close. The model can only recommend.

## What it may close
Only alerts that meet **all** of these (checked in code, never by the model):
- severity is **low or medium** (High/critical are investigated and summarised, never closed)
- Datto confirms `malicious=false` and `threatScore=0`
- verdict `benign` with `high` confidence
- at least 2 evidence items, and at least one cites a tool that actually returned data
- no red flags from tools (VirusTotal detections, domain registered < 30 days ago)

Suspicious or malicious verdicts are **not closed**: they get a comment on the alert (and a Teams
message if `TEAMS_WEBHOOK_URL` is set). Everything uncertain stays open for a human.

## Modes (`SENTINEL_INVESTIGATOR_MODE` in Railway)
| value | behavior |
|---|---|
| `observe` (default) | investigates and writes what it WOULD do in the alert comment; closes nothing |
| `active` | closes alerts that pass every guardrail |
| `legacy` | the old single-shot Claude triage (no guardrails; not recommended) |

Note: in `observe`, alerts that the old AI path used to close stay open too. Deterministic
rules (known-safe destinations, known-benign patterns, trusted signatures) are unchanged.

## Other variables (all optional)
- `VIRUSTOTAL_API_KEY` adds the VirusTotal tool (the free key is enough)
- `TEAMS_WEBHOOK_URL` posts escalations to Teams (Workflows "when a webhook request is received")
- `SENTINEL_INVESTIGATE_HIGH=false` stops investigating High alerts (default: investigate and summarise)
- `SENTINEL_MAX_INVESTIGATIONS_PER_HOUR` (default 60) and `SENTINEL_MAX_CONCURRENT_INVESTIGATIONS` (default 2)
- `SENTINEL_INVESTIGATOR_MODEL` (default `claude-sonnet-4-6`)
- `SENTINEL_AUTO_SUPPRESSION=deterministic` re-enables automatic suppression rules for the
  deterministic tiers only. Default is **off**. AI decisions never create suppression rules.

## Why suppression rules are off
A suppression rule hides all FUTURE alerts of a rule + parent-process pair (for example
"Linux Upload using curl or wget" from `zsh`) across every organization. Creating one from a
single automatic decision would blind the EDR to real attacks that look the same.
Review existing rules named `SENTINEL - ...` in Datto EDR.

## Safety properties (covered by tests)
- Secrets (Bearer tokens, presigned-URL signatures, API keys, JWTs) are removed before anything
  goes to Claude, VirusTotal, Teams or the logs.
- The page reader only reaches the public internet: private, loopback, link-local and cloud
  metadata addresses are refused, connections are pinned to the checked IP, no cookies, no
  JavaScript, size and time limits, query strings are stripped from URLs.
- Alert text is treated as untrusted data. A fooled model still cannot close an alert without
  tool evidence and Datto's own confirmation.

## Try it on a real alert (read-only)
    node server/investigate_alert.js <alertId>

## Tests (offline, no keys needed)
    node server/test_investigator.js
    node server/test_webhook_gating.js

## Rollout
1. Deploy in `observe` and leave it 3-5 days.
2. Read the `[OBSERVE MODE - would auto-resolve]` comments and the `Not auto-closed:` reasons.
   If a legitimate alert is blocked because Datto's webhook payload lacks `malicious` or
   `threatScore`, the reason will say so.
3. When its decisions match yours, set `SENTINEL_INVESTIGATOR_MODE=active`.

## Rollback
Set `SENTINEL_INVESTIGATOR_MODE=legacy` in Railway (no redeploy of code needed), or
`git revert` the commit. Original files are also kept as `*.pre-investigator.bak` locally.
