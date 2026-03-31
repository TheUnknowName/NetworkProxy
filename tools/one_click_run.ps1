$ErrorActionPreference = "Stop"

$repo_root = Split-Path -Parent $PSScriptRoot
Set-Location $repo_root

$report_dir = Join-Path $repo_root "reports"
$summary_path = Join-Path $report_dir "one_click_summary.md"

New-Item -ItemType Directory -Force -Path $report_dir | Out-Null

Write-Output "[1/5] Configure CMake"
cmake -S . -B build
if ($LASTEXITCODE -ne 0) { throw "cmake configure failed" }

Write-Output "[2/5] Build Debug"
cmake --build build --config Debug
if ($LASTEXITCODE -ne 0) { throw "cmake build failed" }

Write-Output "[3/5] Run CTest (Debug)"
ctest --test-dir build -C Debug --output-on-failure
if ($LASTEXITCODE -ne 0) { throw "ctest failed" }

Write-Output "[4/5] Run E2E Validation"
powershell -ExecutionPolicy Bypass -File (Join-Path $repo_root "tools\e2e_clean_validation.ps1")
if ($LASTEXITCODE -ne 0) { throw "e2e validation failed" }

Write-Output "[5/5] Build summary report"
$timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
$packet_report = Join-Path $report_dir "packet_smoke_report.md"
$e2e_report = Join-Path $report_dir "e2e_validation_report.md"

$packet_status = if (Test-Path $packet_report) { "present" } else { "missing" }
$e2e_status = if (Test-Path $e2e_report) { "present" } else { "missing" }

$summary = @()
$summary += "# One Click Run Summary"
$summary += ""
$summary += "- generated_at: $timestamp"
$summary += "- build_config: Debug"
$summary += "- ctest: PASS"
$summary += "- e2e: PASS"
$summary += "- packet_report: $packet_status"
$summary += "- e2e_report: $e2e_status"
$summary += ""
$summary += "## Report Files"
$summary += "- reports/packet_smoke_report.md"
$summary += "- reports/e2e_validation_report.md"
$summary += "- reports/one_click_summary.md"

$summary | Set-Content -Encoding ascii $summary_path
Write-Output "One click run PASS"
Write-Output "Summary: $summary_path"
