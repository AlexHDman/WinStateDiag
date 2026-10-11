@echo off
rem WinStateDiag release gate launcher (one UAC prompt).
rem Usage: scripts\release\release_gate.cmd <expected-head-sha>
rem All logic lives in release_gate.ps1 (fails closed; see its header).
setlocal EnableExtensions
if "%~1"=="" (
  echo Usage: %~nx0 ^<expected-head-sha^>
  exit /b 2
)
net session >nul 2>&1
if errorlevel 1 (
  echo Requesting administrator rights...
  powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -ArgumentList '%~1' -Verb RunAs"
  exit /b
)
rem Windows PowerShell 5.1 must not inherit a PowerShell 7 module path.
set "PSModulePath="
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0release_gate.ps1" -ExpectedHead %~1
set "RC=%ERRORLEVEL%"
if "%RC%"=="0" ( echo GATE PASS ) else ( echo GATE FAIL ^(exit %RC%^) )
pause
exit /b %RC%
