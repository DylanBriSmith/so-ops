# so-ops correlate -- scheduled task runner
# Runs every 15 minutes: rule-based triage then LLM-backed correlate.

# Prefer machine-wide Python (survives user-level Python uninstall)
$GlobalPythonScripts = "C:\Program Files\Python314\Scripts"
if (Test-Path $GlobalPythonScripts) {
    $env:Path = "$GlobalPythonScripts;$env:Path"
}

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
so-ops correlate --lookback-minutes 30 --skip-vuln
