# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project

so-ops is an LLM-powered alert triage, health reporting, and vulnerability scanning companion for Security Onion. It runs on a separate VM/workstation — never on the SO sensor itself — and connects to SO's Elasticsearch over HTTPS port 9200.

## Zero-dependency constraint

The project intentionally has no third-party Python runtime dependencies. `src/so_ops/` uses only the standard library (urllib, ssl, json, logging, smtplib, subprocess). Do not introduce pip packages into `dependencies` in pyproject.toml. Dev-only tools (e.g. pytest, ruff) belong under `[project.optional-dependencies]` or as separate installs, never in `dependencies`.

## CLI entry point

```
so-ops init           # interactive setup wizard
so-ops triage         # query ES alerts, classify via LLM, notify
so-ops triage --dry-run   # rule-based only, no LLM (used by scheduled task)
so-ops health         # collect 24h metrics, generate LLM briefing
so-ops scan           # nmap + nuclei vuln scan
so-ops correlate      # cross-reference alerts with vulnscan, LLM brief, notify
so-ops correlate --lookback-hours 48      # default
so-ops correlate --lookback-minutes 20   # sub-hour window (scheduled use)
so-ops status         # show last run times and state
so-ops config-check   # validate config.toml
so-ops test-notify    # send a test notification
```

The `so-ops` executable is installed at `C:\Users\dnsh\AppData\Roaming\Python\Python314\Scripts\so-ops.exe`.
That Scripts directory has been added to the user PATH — a new PowerShell window is required for it to take effect.

To run triage manually (env vars must be set each session unless added to PowerShell profile):

```powershell
$env:SO_OPS_ES_PASSWORD = '123456'
$env:SO_OPS_OR_API_KEY  = 'sk-or-v1-...'
$env:SO_OPS_CONFIG      = 'C:\CBScripts\so-ops\config.toml'
so-ops triage
```

To re-run triage against already-seen alerts (reset the cursor):

```powershell
Remove-Item "C:\CBScripts\so-ops-data\state\triage.json" -Force
```

## Configuration

Config is a TOML file searched in order: `$SO_OPS_CONFIG` env var → `~/.config/so-ops/config.toml` → `./config.toml`. See `config.example.toml` for all options.

Key env vars:
- `SO_OPS_ES_PASSWORD` — overrides `[elasticsearch].password` in config
- `SO_OPS_OR_API_KEY`  — OpenRouter API key
- `SO_OPS_CONFIG`      — explicit path to config.toml

Secrets live in `C:\CBScripts\so-ops\.env` (never committed). The scheduled task script loads this file at runtime.

SSL verification is disabled (`verify_ssl = false`) because Security Onion uses self-signed certs.

## LLM providers

Two providers are supported, selected via `llm_provider` in config.toml:

- `ollama` — local inference, requires `[ollama]` section
- `openrouter` — cloud inference via OpenAI-compatible API, requires `[openrouter]` section and `SO_OPS_OR_API_KEY`

Current deployment uses **openrouter** with model `google/gemini-2.5-flash-lite`.

## Security Onion instance

- Manager: `192.168.1.231` (hostname: `HOSVRSOMGR.cdnbrg.com`)
- Elasticsearch: `https://192.168.1.231:9200`
- ES user: `soc_viewer` (SO web UI account — has read access to alert indices)
- Firewall rule required on SO manager: `sudo so-firewall includehost elasticsearch_rest <this-machine-ip> && sudo so-firewall apply`
- Kibana/SO web UI: `https://192.168.1.231` (port 443)
- SO version: 3.0

The `soc_viewer` account is a Security Onion web UI account, not a native ES account. It has read access to `logs-suricata.alerts-so`, `logs-zeek-so`, and `logs-detections.alerts-so` but cannot run cluster-level API calls (`_cluster/health` returns 403 — this is fine, so-ops doesn't need it).

## Notifications

Teams is **enabled**. All other channels are disabled.

Configured channels:
- `teams` — Microsoft Teams via Power Automate HTTP webhook, sends Adaptive Cards. **Test carefully** — the Teams channel is live and shared.
- `ntfy` — topic `so-ops-test`, disabled
- `email`, `discord`, `slack`, `sms`, `gotify`, `webhook` — disabled

The Teams card body is the LLM analyst brief followed by a `---` divider and a structured per-pattern breakdown (confidence, alert count, time window, pivot IP, peer, targets, port, top rules, reason). Real IPs are shown in the detail block (notification is internal only). IPs are scrubbed before sending to the cloud LLM.

The Teams provider (`notify.py:_send_teams`) sends an Adaptive Card payload matching the existing Power Automate webhook format. Payload shape: `{"type":"message","attachments":[{"contentType":"application/vnd.microsoft.card.adaptive","content":{...}}]}`.

## Scheduled task

A Windows Task Scheduler task named `so-ops-correlate` runs every 15 minutes:

```
so-ops triage --dry-run       # rule-based triage (fast, no LLM), feeds triage.jsonl
so-ops correlate --lookback-minutes 20   # pattern detection + Gemini brief + Teams notify
```

Script: `C:\CBScripts\so-ops\run_correlate.ps1` — loads secrets from `.env`, sets `SO_OPS_CONFIG`.

To trigger manually: `Start-ScheduledTask -TaskName "so-ops-correlate"`
To check status: `Get-ScheduledTaskInfo -TaskName "so-ops-correlate"`

## Correlate tool

`tools/correlate.py` runs in three passes:

**Pass 1 — Alert × alert pattern detection** (no LLM, always runs):
14 behavioural patterns detected from `triage.jsonl`:

| Pattern | Confidence | Trigger |
|---|---|---|
| `scan_to_exploit` | HIGH | same src fires scan + exploit rules |
| `targeted_host` | HIGH | same dest hit by scan + exploit |
| `inbound_sweep` | HIGH | external src → 4+ internal hosts |
| `internal_exploit` | HIGH | internal src → internal dest, high-sev rules |
| `c2_beacon` | HIGH | 3+ TROJAN/MALWARE rules on same src→dest pair |
| `lateral_movement` | MEDIUM | src → 4+ distinct internal dests |
| `port_sweep` | MEDIUM | same src, same port, 3+ hosts |
| `multi_rule_pair` | MEDIUM | 4+ distinct rules on same src→dest pair |
| `brute_force` | MEDIUM | 10+ alerts on auth port(s) same pair |
| `high_volume_src` | MEDIUM/LOW | 30+ alerts from one src |
| `single_rule_flood` | MEDIUM/LOW | same rule fired 100+ times from one src |
| `src_ip_pivot` | LOW | src not already flagged, 5+ alerts, 3+ non-INFO categories |
| `dest_ip_pivot` | LOW | dest not already flagged, 5+ rules, 2+ sources |
| `dest_port_pivot` | LOW | 3+ distinct srcs, 5+ alerts on same port |

Auth ports for brute_force: 21, 22, 23, 110, 143, 389, 445, 1433, 3306, 3389, 5432, 5900, 5984, 5985, 5986.

Deduplication: high_volume_src skips if scan_to_exploit/lateral_movement already matched that src. inbound_sweep skips if scan_to_exploit matched. src_ip_pivot skips IPs already used as pivot. dest_ip_pivot skips IPs already used as dest pivot. dest_port_pivot skips ports already covered by port_sweep.

Each pattern carries: `pattern_type`, `confidence`, `pivot_ip`, `pivot_role`, `peer_ip`, `dest_ips`, `dest_port`, `rule_names` (up to 20), `categories`, `alert_count`, `time_first`, `time_last`, `recommended_verdict`, `reason`, `community_ids` (up to 10 from matching alerts).

**Pass 2 — Alert × vulnscan cross-reference** (skipped if no scan data):
Matches alert IPs against nmap XML + nuclei JSONL. Match types (descending confidence): `exact_cve` → `nuclei_cve` → `service_keyword` → `targeted_host`. Recommends verdict upgrades when confidence exceeds current triage verdict. Each vuln finding carries `community_id` from the originating triage alert.

**Pass 3 — LLM analyst brief** (skipped if no HIGH/MEDIUM findings):
HIGH+MEDIUM patterns + vuln findings are sent to Gemini via OpenRouter. IPs are scrubbed to `INT-001`/`EXT-001` tokens before the cloud call (controlled by `triage.scrub_ips` in config). Returns a prioritised analyst brief. On failure, report and notifications proceed without it.

## triage.jsonl fields

Each line written by `_log_triage_result()`:
`alert_id`, `alert_timestamp`, `rule_name`, `source_ip`, `dest_ip`, `source_port`, `dest_port`, `protocol`, `community_id`, `verdict`, `confidence`, `method`, `reason`, `escalated`, `correlated_rules`, `notification_sent`

`community_id` is the ECS `network.community_id` field from Suricata — a hash of the 5-tuple. Used by correlate to thread patterns back to the originating flow.

## Development setup

```bash
pip install -e ".[dev]"   # installs so-ops in editable mode
pytest                     # run tests from repo root
ruff check src/ tests/     # lint
ruff format src/ tests/    # format
```

**Linter caveat**: ruff runs after every Edit. If you add an import in one edit and the function using it in a separate edit, ruff will remove the import as unused between the two edits. Always add imports in the same edit as the code that uses them.

## State and logging

Each tool persists a JSON cursor in `data_dir/state/` (configured via `[paths].data_dir`, currently `C:/CBScripts/so-ops-data`). The cursor prevents re-processing alerts already seen.

Logs are written to three destinations simultaneously:
- stderr
- Rotating file log in `data_dir/logs/` (5 MB max, 3 backups)
- Append-only JSONL audit trail in `data_dir/logs/` (never rotated)

Correlate findings are also appended to `data_dir/logs/correlate_findings.jsonl`.

## Architecture

```
src/so_ops/
  cli.py          — argparse entry point, dispatches to tools/
  config.py       — TOML loader + typed dataclasses
  clients/
    base.py           — LLMClient Protocol (structural subtyping)
    elasticsearch.py  — urllib + Basic Auth + SSL (no requests)
    ollama.py         — POST to local Ollama REST API
    openrouter.py     — POST to OpenRouter /chat/completions
    notify.py         — email, Discord, Slack, ntfy, Gotify, SMS, Webhook, Teams
  tools/
    triage.py     — alert triage logic
    health.py     — health report generation
    vulnscan.py   — nmap/nuclei orchestration
    correlate.py  — 3-pass correlation engine (alert patterns, vuln cross-ref, LLM brief)
scripts/
  mock_triage.py  — full end-to-end triage run without Elasticsearch
run_correlate.ps1 — scheduled task runner (loads .env, triage --dry-run + correlate)
```

## LLM behavior notes

- Triage uses `llm_temperature = 0.1` (deterministic classification)
- Health reports use `llm_temperature = 0.3`
- Correlate LLM brief uses `temperature = 0.3`
- Network zone context (`[network].internal_prefixes`) is injected into prompts — missing zones degrade classification accuracy
- Escalation rules in `[triage]` bump verdicts to MEDIUM/HIGH regardless of LLM output; auto-noise signatures skip LLM entirely
- IPs are scrubbed before any cloud LLM call (`scrub_ips = true` in config)

## Git

Fork: `https://github.com/DylanBriSmith/so-ops` (push target)
Upstream: `https://github.com/benolenick/so-ops` (PR target)

Remotes: `fork` = DylanBriSmith, `origin` = benolenick. Push to `fork`, not `origin`.

```bash
git push fork main
```

Commit directly to main. No branch or PR conventions.
