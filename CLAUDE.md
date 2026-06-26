# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project

so-ops is an LLM-powered alert triage, health reporting, and vulnerability scanning companion for Security Onion. It runs on a separate VM/workstation — never on the SO sensor itself — and connects to SO's Elasticsearch over HTTPS port 9200.

## Zero-dependency constraint

The project intentionally has no third-party Python runtime dependencies. `src/so_ops/` uses only the standard library (urllib, ssl, json, logging, smtplib, subprocess). Do not introduce pip packages into `dependencies` in pyproject.toml. Dev-only tools (e.g. pytest, ruff) belong under `[project.optional-dependencies]` or as separate installs, never in `dependencies`.

## CLI entry point

```
so-ops init           # interactive setup wizard
so-ops triage         # query ES alerts, classify via Ollama, notify
so-ops health         # collect 24h metrics, generate LLM briefing
so-ops scan           # nmap + nuclei vuln scan
so-ops status         # show last run times and state
so-ops config-check   # validate config.toml
so-ops test-notify    # send a test notification
```

## Configuration

Config is a TOML file searched in order: `$SO_OPS_CONFIG` env var → `~/.config/so-ops/config.toml` → `./config.toml`. See `config.example.toml` for all options.

Key env vars:
- `SO_OPS_ES_PASSWORD` — overrides `[elasticsearch].password` in config
- `SO_OPS_CONFIG` — explicit path to config.toml

SSL verification is disabled by default (`verify_ssl = false`) because Security Onion uses self-signed certs.

## Development setup

```bash
pip install -e ".[dev]"   # installs so-ops in editable mode
pytest                     # run tests from repo root
ruff check src/ tests/     # lint
ruff format src/ tests/    # format
```

## State and logging

Each tool persists a JSON cursor in `data_dir/state/` (configured via `[paths].data_dir`). The cursor prevents re-processing alerts already seen. Do not delete state files to "reset" without understanding the impact on alert deduplication.

Logs are written to three destinations simultaneously:
- stderr (captured by systemd journal)
- Rotating file log in `data_dir/logs/` (5 MB max, 3 backups)
- Append-only JSONL audit trail in `data_dir/logs/` (never rotated)

## Architecture

```
src/so_ops/
  cli.py          — argparse entry point, dispatches to tools/
  config.py       — TOML loader + typed dataclasses
  clients/
    elasticsearch.py  — urllib + Basic Auth + SSL (no requests)
    ollama.py         — POST to local Ollama REST API
    notify.py         — email, Discord, Slack, ntfy, Gotify, SMS, Webhook
  tools/
    triage.py     — alert triage logic
    health.py     — health report generation
    vulnscan.py   — nmap/nuclei orchestration
```

## LLM behavior notes

- Triage uses `llm_temperature = 0.1` (deterministic classification)
- Health reports use `llm_temperature = 0.3`
- Network zone context (`[network].internal_prefixes`) is injected into prompts — missing zones degrade classification accuracy
- Escalation rules in `[triage]` bump verdicts to MEDIUM/HIGH regardless of LLM output; auto-noise signatures skip LLM entirely

## Deployment

Use `scripts/deploy.sh` for SSH-based deployment. It handles rsync (Linux) vs tar+ssh (Windows/Git Bash) automatically. Systemd units live in `systemd/` and are installed by the deploy script with sudo.

## Git

Commit directly to main. No branch or PR conventions.
