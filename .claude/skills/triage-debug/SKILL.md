---
name: triage-debug
description: Step-by-step debug flow for alert triage failures — Elasticsearch connectivity, Ollama availability, notification delivery, and state cursor issues. Use when `so-ops triage` errors or produces no output.
---

Walk through the triage debug flow for this so-ops installation.

## Step 1: Config check

```bash
so-ops config-check
```
Look for missing required fields (`[elasticsearch].host`, `[ollama].url`, `[paths].data_dir`). Fix any reported errors before continuing.

## Step 2: Elasticsearch connectivity

Check whether SO's ES is reachable:
```bash
curl -k -u <es_user>:<es_password> https://<so_manager>:9200/_cluster/health
```
- `yellow` or `green` → ES is up, proceed.
- Connection refused / timeout → firewall or wrong host. Check `[elasticsearch].host` in config.
- 401 → wrong credentials. Check `SO_OPS_ES_PASSWORD` env var or `[elasticsearch].password`.
- SSL error with `verify_ssl = true` → set `verify_ssl = false` (SO uses self-signed certs).

## Step 3: Suricata index query

Verify the alert index exists and has recent data:
```bash
curl -k -u <user>:<pass> "https://<host>:9200/<suricata_index>/_count"
```
A count of 0 means no alerts in the index (either quiet network or wrong index name in `[elasticsearch.indices].suricata`).

## Step 4: Ollama availability

```bash
curl http://localhost:11434/api/tags
```
- Lists models → Ollama is running. Confirm the model in `[ollama].model` appears in the list.
- Connection refused → `systemctl start ollama` (or check Ollama install).
- Model missing → `ollama pull <model_name>`.

## Step 5: State cursor

The triage cursor is a JSON file at `<data_dir>/state/triage_state.json`. If it points to a timestamp beyond current alerts, triage finds nothing to process.

To inspect: `cat <data_dir>/state/triage_state.json`

To reset (re-process recent alerts): delete or zero out the `last_event_time` field. Understand that this may re-notify on alerts already seen.

## Step 6: Notification test

```bash
so-ops test-notify
```
If this fails, check the relevant `[notifications.*]` section in config. Common issues:
- SMTP: wrong port, TLS mode, or app password required
- Discord/Slack: webhook URL expired or wrong channel
- ntfy/Gotify: service not running or wrong URL

## Step 7: Run with verbose logging

```bash
so-ops triage 2>&1 | tee /tmp/triage-debug.log
```
Review the log for the first ERROR or WARNING line and address it directly.
