param(
    [switch]$Clean
)

$ErrorActionPreference = "Stop"
$Root = Resolve-Path (Join-Path $PSScriptRoot "..")
Set-Location $Root

python -m pip install --upgrade pip
python -m pip install -e ".[package]"

if ($Clean) {
    Remove-Item -Recurse -Force "build", "dist" -ErrorAction SilentlyContinue
}

python -m PyInstaller --clean flowpilot.spec

$AppDir = Join-Path $Root "dist\FlowPilot"
$PrivateDir = Join-Path $AppDir "private"
New-Item -ItemType Directory -Force -Path $PrivateDir | Out-Null

$EnvPath = Join-Path $PrivateDir ".env"
if (-not (Test-Path $EnvPath)) {
    Copy-Item (Join-Path $Root ".env.example") $EnvPath
}

Write-Host ""
Write-Host "FlowPilot Windows package created at:" -ForegroundColor Green
Write-Host "  $AppDir"
Write-Host ""
Write-Host "User-editable config:"
Write-Host "  $EnvPath"
Write-Host ""
Write-Host "Run:"
Write-Host "  .\dist\FlowPilot\flowpilot.exe models"
Write-Host "  .\dist\FlowPilot\flowpilot.exe analyze C:\path\capture.pcap --no-llm"
