# so-ops correlate — scheduled task runner
# Runs every 15 minutes, looks back 20 minutes of triage alerts.
#
# Secrets are loaded from environment variables set in the Task Scheduler action
# or from Windows System Environment Variables.
# DO NOT hardcode secrets here.
#
# Required env vars (set in Task Scheduler or System Environment Variables):
#   SO_OPS_ES_PASSWORD  — Elasticsearch password
#   SO_OPS_OR_API_KEY   — OpenRouter API key

$env:SO_OPS_CONFIG = "C:\CBScripts\so-ops\config.toml"

# Run triage first (LLM classifies new alerts), then correlate on last 20 min
so-ops triage
so-ops correlate --lookback-minutes 20
