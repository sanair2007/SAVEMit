param(
    [Parameter(Mandatory = $true)]
    [string]$TargetWorkspace,
    [switch]$Force
)

$savemitRoot = Split-Path $PSScriptRoot -Parent
$targetPath = (Resolve-Path -LiteralPath $TargetWorkspace).Path
$pluginSource = Join-Path $savemitRoot "plugins\antigravity"
$pluginTarget = Join-Path $targetPath ".agents\plugins\savemit-security"
$workspaceConfig = Join-Path $targetPath ".agents\mcp_config.json"

if ((Test-Path -LiteralPath $pluginTarget) -and -not $Force) {
    Write-Output "Plugin already exists at $pluginTarget; keeping it."
} else {
    New-Item -ItemType Directory -Path $pluginTarget -Force | Out-Null
    Copy-Item -LiteralPath (Join-Path $pluginSource "plugin.json") -Destination $pluginTarget -Force
    Copy-Item -LiteralPath (Join-Path $pluginSource "skills") -Destination $pluginTarget -Recurse -Force
}

$config = Get-Content -Raw (Join-Path $pluginSource "mcp_config.json.example")
$escapedRoot = $savemitRoot.Replace("\", "\\")
$config = $config.Replace("C:\\absolute\\path\\to\\SAVEMit", $escapedRoot)

if ((Test-Path -LiteralPath $workspaceConfig) -and -not $Force) {
    throw "MCP configuration already exists at $workspaceConfig. Rerun with -Force only if you want SAVEMit to replace it."
}

$config | Set-Content -LiteralPath (Join-Path $pluginTarget "mcp_config.json") -Encoding utf8
$config | Set-Content -LiteralPath $workspaceConfig -Encoding utf8

Write-Output "Installed SAVEMit plugin in $pluginTarget and MCP configuration in $workspaceConfig"
