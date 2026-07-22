$EnvFile = "C:\CBScripts\so-ops\.env"
if (Test-Path $EnvFile) {
    Get-Content $EnvFile | ForEach-Object {
        if ($_ -match '^\s*([^#=]+?)\s*=\s*(.+)\s*$') {
            [System.Environment]::SetEnvironmentVariable($Matches[1], $Matches[2], "Process")
        }
    }
}
$env:SO_OPS_CONFIG = "C:\CBScripts\so-ops\config.toml"
so-ops correlate --lookback-minutes 20 --skip-vuln
