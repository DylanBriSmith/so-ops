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
so-ops health         # collect 24h metrics, generate LLM briefing
so-ops scan           # nmap + nuclei vuln scan
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
Remove-Item "C:\CBFiles\so-ops-data\state\triage.json" -Force
```

## Configuration

Config is a TOML file searched in order: `$SO_OPS_CONFIG` env var → `~/.config/so-ops/config.toml` → `./config.toml`. See `config.example.toml` for all options.

Key env vars:
- `SO_OPS_ES_PASSWORD` — overrides `[elasticsearch].password` in config
- `SO_OPS_OR_API_KEY`  — OpenRouter API key
- `SO_OPS_CONFIG`      — explicit path to config.toml

SSL verification is disabled (`verify_ssl = false`) because Security Onion uses self-signed certs.

## LLM providers

Two providers are supported, selected via `llm_provider` in config.toml:

- `ollama` — local inference, requires `[ollama]` section
- `openrouter` — cloud inference via OpenAI-compatible API, requires `[openrouter]` section and `SO_OPS_OR_API_KEY`

Current deployment uses **openrouter** with model `anthropic/claude-haiku-4-5`.

## Security Onion instance

- Manager: `192.168.1.231` (hostname: `HOSVRSOMGR.cdnbrg.com`)
- Elasticsearch: `https://192.168.1.231:9200`
- ES user: `soc_viewer` (SO web UI account — has read access to alert indices)
- Firewall rule required on SO manager: `sudo so-firewall includehost elasticsearch_rest <this-machine-ip> && sudo so-firewall apply`
- Kibana/SO web UI: `https://192.168.1.231` (port 443)
- SO version: 3.0

The `soc_viewer` account is a Security Onion web UI account, not a native ES account. It has read access to `logs-suricata.alerts-so`, `logs-zeek-so`, and `logs-detections.alerts-so` but cannot run cluster-level API calls (`_cluster/health` returns 403 — this is fine, so-ops doesn't need it).

## Notifications

All notification channels are currently **disabled** in config.toml. Enable selectively when ready.

Configured channels:
- `teams` — Microsoft Teams via Power Automate HTTP webhook, sends Adaptive Cards. **Test carefully** — the Teams channel is live and shared. Always test with `so-ops test-notify` before enabling on a scheduled run.
- `ntfy` — topic `so-ops-test`, push notifications to phone
- `email`, `discord`, `slack`, `sms`, `gotify`, `webhook` — configured but not set up

The Teams provider (`notify.py:_send_teams`) sends an Adaptive Card payload matching the existing Power Automate webhook format used by other tools at Canadian Bearings. Payload shape: `{"type":"message","attachments":[{"contentType":"application/vnd.microsoft.card.adaptive","content":{...}}]}`.

## Development setup

```bash
pip install -e ".[dev]"   # installs so-ops in editable mode
pytest                     # run tests from repo root
ruff check src/ tests/     # lint
ruff format src/ tests/    # format
```

## State and logging

Each tool persists a JSON cursor in `data_dir/state/` (configured via `[paths].data_dir`, currently `C:/CBFiles/so-ops-data`). The cursor prevents re-processing alerts already seen.

Logs are written to three destinations simultaneously:
- stderr
- Rotating file log in `data_dir/logs/` (5 MB max, 3 backups)
- Append-only JSONL audit trail in `data_dir/logs/` (never rotated)

## Architecture

```
src/so_ops/
  cli.py          — argparse entry point, dispatches to tools/
  config.py       — TOML loader + typed dataclasses
  clients/
    base.py           — LLMClient Protocol (structural subtyping)
    elasticsearch.py  — urllib + Basic Auth + SSL (no requests)
    ollama.py         — POST to local Ollama REST API
    openrouter.py     — POST to OpenRouter /chat/completions (NEW)
    notify.py         — email, Discord, Slack, ntfy, Gotify, SMS, Webhook, Teams (NEW)
  tools/
    triage.py     — alert triage logic
    health.py     — health report generation
    vulnscan.py   — nmap/nuclei orchestration
scripts/
  mock_triage.py  — full end-to-end triage run without Elasticsearch (NEW)
```

## LLM behavior notes

- Triage uses `llm_temperature = 0.1` (deterministic classification)
- Health reports use `llm_temperature = 0.3`
- Network zone context (`[network].internal_prefixes`) is injected into prompts — missing zones degrade classification accuracy
- Escalation rules in `[triage]` bump verdicts to MEDIUM/HIGH regardless of LLM output; auto-noise signatures skip LLM entirely

## Git

Fork: `https://github.com/DylanBriSmith/so-ops` (push target)
Upstream: `https://github.com/benolenick/so-ops` (PR target)

Remotes: `fork` = DylanBriSmith, `origin` = benolenick. Push to `fork`, not `origin`.

```bash
git push fork main
```

Commit directly to main. No branch or PR conventions.
