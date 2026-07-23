# Alert noise review — 2026-07-23

Two things investigated in this session:
1. What's dominating the correlation engine's noise overnight (7/22 → 7/23)
2. Why a specific Suricata severity-1 "Windows 98" alert around 7/22 ~8pm never
   showed up in a `so-ops correlate` notification

---

## 1. Biggest noise source: `192.168.1.240` (this workstation's `so-ops scan`)

Analyzed ~2,357 correlation findings logged overnight in `correlate_findings.jsonl`.

`config.toml` runs `so-ops scan` (nmap `-sV --script=vulners -T4 --open`) against
`192.168.0.0/24` and `192.168.1.0/24`. That scan is triggering a pile of Suricata
signatures on itself that look like attacks but are actually just nmap's service
probes:

| Rule | Count | Notes |
|---|---|---|
| ET SCAN MS Terminal Server Traffic on Non-standard Port | 577 | nmap RDP probe |
| ET INFO RMI Request Outbound | 468 | nmap service probe |
| ET INFO Outbound MSSQL Connection to Non-Standard Port - Likely Malware | 448 | nmap service probe |
| ET INFO GIOP/IIOP Request Outbound | 440 | nmap service probe |
| ET SCAN Nmap Scripting Engine User-Agent Detected | 297 | nmap NSE |
| ET SCAN Possible Nmap User-Agent Observed | 297 | nmap NSE |
| ET SCAN RDP Connection Attempt from Nmap | 213 | nmap RDP probe |
| ET SCAN Potential SSH Scan OUTBOUND | 187 | nmap SSH probe |

**Impact on correlation output:**
- **28.9%** of all findings (682 / 2,357) involve `192.168.1.240` as pivot or peer
- `multi_rule_pair`: **95.5%** of these came from `.240` alone
- `port_sweep`: **45.8%**
- `brute_force`: **34.5%** — nmap's SSH/RDP/SMB service probes against many hosts
  get miscategorized as brute-force attempts

`[triage.escalation].minimum_medium` includes `"ET SCAN"`, so this traffic is
force-escalated to at least MEDIUM in triage before it even reaches correlation —
it can never be filtered out by the LLM.

The genuinely interesting HIGH-confidence pattern types (`internal_exploit`,
`inbound_sweep`) had **0%** contamination from `.240` — those stayed clean.

**Status:** confirmation still needed — is `192.168.1.240` this workstation?
No fix has been applied yet. Recommended options when ready:
- Add a config exclude-list and skip this IP in `correlate`'s pattern detection, and/or
- Exclude it from `[triage.escalation]` too

---

## 2. Why the "Windows 98" alert (Suricata severity 1) never reached `correlate`

### The alert

- **Rule:** `ET INFO Windows 98 User-Agent Detected - Possible Malware or Non-Updated System`
- **Suricata `rule_severity`:** 1, but **`sig_severity` (ET metadata): "Informational"**
- **Source:** `192.168.129.20` → many internal destinations on port 80
  (`192.168.128.100`, `192.168.127.101`, `192.168.151.113`, `192.168.131.100`,
  `192.168.58.102`, `192.168.147.108`, `192.168.142.101`, and more — 7+ distinct
  hosts in a ~3 minute burst)
- **Correlated on the same flow with:** `ET HUNTING GENERIC SUSPICIOUS POST to
  Dotted Quad with Fake Browser 1`, `ET INFO Unsupported/Fake Internet Explorer
  Version MSIE 5.`
- **Alert timestamps:** `2026-07-22T23:00:01Z` – `2026-07-22T23:03:02Z` (≈ 7:00–7:03pm EDT)
- **Triaged (written to `triage.jsonl`) at:** `2026-07-22T23:13:43Z` (≈ 7:13pm EDT)
- **Verdict assigned by dry-run triage: `HIGH`**

### Bug #1 — severity-mapping bug inflated this to HIGH

`triage.py`'s dry-run classifier does:

```python
sev_map = {1: "HIGH", 2: "MEDIUM", 3: "LOW"}
```

This assumes Suricata's numeric `rule_severity` always means "1 = most severe."
For this rule, `rule_severity` is `1` but the rule's own ET metadata
(`sig_severity`) says **"Informational"** — the numeric severity here does not
track real-world danger, and the code never cross-checks against `sig_severity`.
Net effect: a purely informational signature gets force-classified `HIGH`. This
is a general bug, not specific to this one alert — worth a proper fix (e.g. use
`sig_severity` as the primary signal, or at least sanity-check `rule_severity` vs
`sig_severity` before assigning HIGH).

**Status:** not fixed yet — flagged for a follow-up change.

### Bug #2 — the alert fell into a correlate scheduling gap, caused by an
unhandled crash in pattern detection (confirmed root cause, now fixed)

This is the main reason `correlate` never mentioned it, independent of bug #1:

`correlate.log` shows three consecutive scheduled starts:

```
2026-07-22 19:13:48  Starting correlation run: 23:13 UTC   -- never completed (no "Report:" line)
2026-07-22 19:28:52  Starting correlation run: 23:28 UTC   -- never completed (no "Report:" line)
2026-07-22 19:43:49  Starting correlation run: 23:43 UTC   -- completed, Report written 19:45:26
```

The runs at 23:13 and 23:28 UTC started but never finished. Both had trivial
alert volume (211 and 238 unique alerts in their 20-minute window — not a
timeout/load issue), and both died at the exact same point in the log: right
after the last `BRUTE FORCE` line, before pattern detection's own summary log
line. The next run to actually complete was at 23:43 UTC, with a 20-minute
lookback (`--lookback-minutes 20`), so its cutoff was **23:23 UTC**.

The Windows 98 alert burst (23:00:01–23:03:02 UTC) was already **more than 20
minutes old** by the time the 23:43 run finally executed, so `load_triage_entries`
correctly (per its own logic) dropped it as "outside window." It was never seen
by Pass 1 pattern detection or Pass 4's AI triage review — not because it was
judged unimportant, but because of a crash gap plus the fixed 20-minute lookback
having no memory of runs that failed to execute.

**Root cause confirmed and fixed (2026-07-23):** `run_correlate.ps1` now
redirects stderr to `C:\CBScripts\so-ops-data\logs\run_correlate_stderr.log`
and logs a `FAILED with exit code N` marker on non-zero exit. The very next
manual test run captured the real traceback:

```
File "correlate_patterns.py", line 471, in correlate_alert_patterns
    auth_entries = [e for e in pair_entries if int(e.get("dest_port", 0) or 0) in _AUTH_PORTS]
ValueError: invalid literal for int() with base 10: '?'
```

`triage.py` stores `dest_port = "?"` for alerts with no port (e.g. ICMP, which
has no TCP/UDP port). The brute-force detection step in `correlate_patterns.py`
called `int()` on that placeholder without guarding against non-numeric values,
raising an uncaught `ValueError` and killing the whole correlate process
mid-Pass-1 — with zero trace, since stderr wasn't captured. This explains every
silent crash seen in this investigation (both the 211/238-alert case here and
the earlier higher-volume case from 7/22 afternoon): it triggers whenever the
20-minute window contains an ICMP (or other portless) alert sharing a
source/dest pair with enough alerts to reach the brute-force check — independent
of overall alert volume.

**Fix applied:** added a `_port_int()` helper in `correlate_patterns.py` that
falls back to `0` for non-numeric `dest_port` values instead of raising.
Verified with a full manual end-to-end run (`run_correlate.ps1`) — completed
without error, produced 27 patterns, and sent the Teams notification.

### This is not an isolated event — same source IP is a recurring, growing pattern

Searching `correlate_findings.jsonl` for pivot IP `192.168.129.20` (the same
source as the Windows 98 alert) shows it has been triggering `lateral_movement` /
`port_sweep` findings intermittently since at least **2026-06-30**, and the
volume has been **escalating sharply**:

| correlated_at | pattern | alert_count | distinct dest hosts |
|---|---|---|---|
| 2026-06-30 | lateral_movement | 161 | 9 |
| 2026-06-30 | lateral_movement | 323 | 9 |
| 2026-07-23 05:44 UTC | lateral_movement | 113 | 10 |
| 2026-07-23 05:59 UTC | lateral_movement | 103 | 9 |
| 2026-07-23 06:45 UTC | lateral_movement | **870** | **~75** |
| 2026-07-23 06:59 UTC | lateral_movement | 423 | 39 |

By early morning 7/23, a single 20-minute correlate window logged **870 alerts**
from this one source touching roughly **75 distinct internal hosts** across
dozens of `/24` subnets. The rule set involved is consistently: `ET HUNTING
GENERIC SUSPICIOUS POST to Dotted Quad with Fake Browser 1`, `ET INFO
Unsupported/Fake Internet Explorer Version MSIE 5.`, `ET INFO Windows 98
User-Agent Detected`.

**This pattern deserves real investigation, not automatic dismissal as noise.**
"POST requests directly to IP addresses with a spoofed old browser user-agent"
is a classic profile for both (a) a legitimate but oddball embedded/IoT device
phoning home (old firmware HTTP client), and (b) malware/beaconing behavior
that disguises itself with old UA strings. The facts that make this ambiguous
rather than clearly benign:
- It has been running for **weeks**, not a one-off
- Its footprint has been **growing** (9 hosts → ~75 hosts)
- It touches dozens of unrelated internal subnets, which is unusual for a
  normal device unless it's an intentional internal scanner/monitoring tool

**Open question — not yet answered:** what is `192.168.129.20`? If it's a known
internal scanner/monitoring appliance, this is safe to add to a noise-exclude
list like `192.168.1.240`. If it's not a known/expected device, this warrants
a real look (what service is running on it, why does it reach so many subnets).

---

## Follow-ups

**Done (2026-07-23):**
- ✅ Item 4 — `run_correlate.ps1` now captures stderr + exit-code failures to
  `run_correlate_stderr.log`.
- ✅ Bug #2's actual root cause — `_port_int()` guard added in
  `correlate_patterns.py` so a portless (`dest_port == "?"`) alert can no
  longer crash the whole correlate run. Verified with a clean manual run.

**Still open — for review:**
1. Confirm whether `192.168.1.240` is this workstation; if so, exclude it from
   `correlate` pattern detection (and optionally `triage.escalation`).
2. Identify what `192.168.129.20` is. Escalating multi-week internal sweep —
   needs a decision (exclude as noise vs. investigate as a possible incident).
3. Fix the `sev_map` bug in `triage.py`'s dry-run path — Suricata numeric
   `rule_severity` should not be trusted as an inverse severity ranking without
   cross-checking `sig_severity`.
