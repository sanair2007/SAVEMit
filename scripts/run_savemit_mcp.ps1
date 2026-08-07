$repositoryRoot = Split-Path $PSScriptRoot -Parent
$environmentRoot = Join-Path $repositoryRoot ".savemit-plugin-venv"
$python = Join-Path $environmentRoot "Scripts\python.exe"

if (-not (Test-Path -LiteralPath $python)) {
    Write-Error "SAVEMit is preparing its local plugin environment. This is a one-time setup."
    & py -3 -m venv $environmentRoot 1>&2
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

    & $python -m pip install --disable-pip-version-check --no-input $repositoryRoot 1>&2
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
}

$env:PYTHONUNBUFFERED = "1"
& $python -m app.mcp.server
exit $LASTEXITCODE
