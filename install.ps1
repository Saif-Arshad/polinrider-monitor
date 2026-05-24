# PolinRider Monitor - installer
# Creates a Desktop shortcut and initialises config.json with sensible defaults.
# Safe to re-run; updates the shortcut to the current location.

$ErrorActionPreference = 'Stop'
$root = $PSScriptRoot

Write-Host ""
Write-Host "PolinRider Monitor - install" -ForegroundColor Cyan
Write-Host ""

# 1. Initialise config if missing
$configFile = Join-Path $root 'config.json'
if (-not (Test-Path $configFile)) {
    $defaults = @{
        ScanPaths = @(
            'C:\Development',
            "$env:USERPROFILE\OneDrive",
            "$env:USERPROFILE\Desktop",
            "$env:USERPROFILE\Documents",
            "$env:USERPROFILE\Downloads",
            "$env:USERPROFILE\source",
            "$env:USERPROFILE\projects"
        )
        MaxFileSize = 10000000
        AutoScanOnLaunch = $false
    }
    $defaults | ConvertTo-Json | Set-Content -LiteralPath $configFile -Encoding utf8
    Write-Host "  Created config.json" -ForegroundColor Green
} else {
    Write-Host "  config.json already present" -ForegroundColor Gray
}

# 2. Create Desktop shortcut
$desktop = [Environment]::GetFolderPath('Desktop')
$lnkPath = Join-Path $desktop 'PolinRider Monitor.lnk'
$vbs     = Join-Path $root 'PolinRiderMonitor.vbs'
if (-not (Test-Path $vbs)) {
    throw "PolinRiderMonitor.vbs not found at $vbs"
}
$wshShell = New-Object -ComObject WScript.Shell
$shortcut = $wshShell.CreateShortcut($lnkPath)
$shortcut.TargetPath = $vbs
$shortcut.WorkingDirectory = $root
$shortcut.IconLocation = "C:\WINDOWS\System32\imageres.dll,16"
$shortcut.Description = "PolinRider Monitor - scan and clean PolinRider/BeaverTail malware"
$shortcut.Save()
Write-Host "  Desktop shortcut created: $lnkPath" -ForegroundColor Green

Write-Host ""
Write-Host "Install complete." -ForegroundColor Green
Write-Host "Launch from your Desktop, or double-click PolinRiderMonitor.vbs in this folder." -ForegroundColor White
Write-Host ""
Write-Host "Tip: Edit config.json to add or remove scan paths." -ForegroundColor Gray
Write-Host ""
