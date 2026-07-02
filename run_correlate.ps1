# so-ops correlate -- scheduled task runner
# Runs every 15 minutes: rule-based triage then LLM-backed correlate.

$EnvFile = "C:\CBScripts\so-ops\.env"
if (Test-Path $EnvFile) {
    Get-Content $EnvFile | ForEach-Object {
        if ($_ -match '^\s*([^#=]+?)\s*=\s*(.+)\s*$') {
            [System.Environment]::SetEnvironmentVariable($Matches[1], $Matches[2], "Process")
        }
    }
}

$env:SO_OPS_CONFIG = "C:\CBScripts\so-ops\config.toml"

so-ops triage --dry-run
so-ops correlate --lookback-minutes 20 --skip-vuln
