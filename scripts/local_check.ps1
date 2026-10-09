# ============================================================
#  Local V2Ray check - runs on laptop every 2h at :20
#  Tests servers with real xray from local location, ping < 100ms
#  Publishes results to GitHub
# ============================================================
$ErrorActionPreference = "Continue"
$repo = "$env:USERPROFILE\Desktop\Vafli_fonarik"
Set-Location $repo

$logDir = Join-Path $repo "logs"
New-Item -ItemType Directory -Force -Path $logDir | Out-Null
$logFile = Join-Path $logDir ("local-{0}.log" -f (Get-Date -Format "yyyyMMdd-HHmmss"))

function Log($msg) {
    $ts = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $line = "$ts $msg"
    Write-Host $line
    Add-Content -Path $logFile -Value $line -Encoding UTF8
}

# Cleanup old logs (>7 days)
Get-ChildItem $logDir -Filter "local-*.log" -ErrorAction SilentlyContinue | Where-Object { $_.LastWriteTime -lt (Get-Date).AddDays(-7) } | Remove-Item -Force -ErrorAction SilentlyContinue

Log "=== Local check started (repo: $repo) ==="

# Locate Python
$py = $null
foreach ($cand in @("python","python3","py")) {
    try {
        $v = & $cand --version 2>&1
        if ($LASTEXITCODE -eq 0) { $py = $cand; Log "Python found: $cand -> $v"; break }
    } catch {}
}
if (-not $py) { Log "ERROR: Python not found in PATH"; exit 1 }

# Pull latest from GitHub
try {
    git pull --rebase 2>&1 | ForEach-Object { Log "git: $_" }
} catch {
    Log "git pull failed: $_ (continuing)"
}

# Ensure deps
& $py -m pip install --quiet --disable-pip-version-check requests PySocks 2>&1 | ForEach-Object { Log "pip: $_" }

# Set local threshold (100ms) before running main.py
$env:MAX_PING_MS = "100"
Log "Local MAX_PING_MS = $env:MAX_PING_MS"

# Run filter
Log "Running main.py..."
& $py "scripts\main.py" 2>&1 | ForEach-Object { Log "py: $_" }
$code = $LASTEXITCODE
Log "main.py exit: $code"
if ($code -ne 0) { Log "main.py failed, no push."; exit $code }

# Commit & push if changed
git add output/mix_sub.txt
git diff --cached --quiet
if ($LASTEXITCODE -eq 0) {
    Log "No changes to commit."
} else {
    $hn = $env:COMPUTERNAME
    $when = Get-Date -Format "yyyy-MM-dd HH:mm"
    git commit -m "Local update from $hn at $when" 2>&1 | ForEach-Object { Log "git: $_" }
    git push 2>&1 | ForEach-Object { Log "git: $_" }
    Log "Pushed to GitHub."
}

Log "=== Local check finished ==="