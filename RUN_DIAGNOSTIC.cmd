@echo off
setlocal
cd /d "%~dp0"
echo NW-E405 Recovery Probe v0.1
echo.
echo This run is diagnostic only. It does NOT format or write the Walkman.
echo Please right-click this file and choose "Run as administrator" if needed.
echo.
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0NW-E405-Recovery-Probe.ps1"
if errorlevel 1 (
  echo.
  echo PowerShell returned errorlevel %errorlevel%.
  pause
)
