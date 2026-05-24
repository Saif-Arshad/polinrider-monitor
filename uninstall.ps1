# PolinRider Monitor - uninstaller
# Removes the Desktop shortcut and any scheduled task. Does NOT delete the
# app files or your scan history.

$ErrorActionPreference = 'Continue'

Write-Host ""
Write-Host "PolinRider Monitor - uninstall" -ForegroundColor Cyan
Write-Host ""

# 1. Remove Desktop shortcut
$desktop = [Environment]::GetFolderPath('Desktop')
$lnkPath = Join-Path $desktop 'PolinRider Monitor.lnk'
if (Test-Path $lnkPath) {
    Remove-Item -LiteralPath $lnkPath -Force
    Write-Host "  Removed Desktop shortcut" -ForegroundColor Green
} else {
    Write-Host "  No Desktop shortcut found" -ForegroundColor Gray
}

# 2. Remove any scheduled task created by previous versions
foreach ($name in @('PolinRider Daily Monitor','PolinRider Monitor')) {
    $task = Get-ScheduledTask -TaskName $name -ErrorAction SilentlyContinue
    if ($task) {
        Unregister-ScheduledTask -TaskName $name -Confirm:$false
        Write-Host "  Removed scheduled task: $name" -ForegroundColor Green
    }
}

Write-Host ""
Write-Host "Uninstall complete." -ForegroundColor Green
Write-Host "App files, config.json, monitor.log, and history.json are left in place." -ForegroundColor Gray
Write-Host "Delete the folder manually if you also want those gone." -ForegroundColor Gray
Write-Host ""
