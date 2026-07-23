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

# Task Scheduler discards this script's own stdout/stderr, so an uncaught
# Python exception (which goes to stderr, not the logging module) would
# otherwise vanish with zero trace. Capture stderr to a dedicated file and
# flag non-zero exit codes so a silent crash is diagnosable next time.
$StderrLog = "C:\CBScripts\so-ops-data\logs\run_correlate_stderr.log"
$RunStamp = Get-Date -Format o

so-ops triage --dry-run 2>> $StderrLog
if ($LASTEXITCODE -ne 0) {
    "[$RunStamp] triage --dry-run FAILED with exit code $LASTEXITCODE" | Out-File -FilePath $StderrLog -Append
}

so-ops correlate --lookback-minutes 20 --skip-vuln 2>> $StderrLog
if ($LASTEXITCODE -ne 0) {
    "[$RunStamp] correlate FAILED with exit code $LASTEXITCODE" | Out-File -FilePath $StderrLog -Append
}
