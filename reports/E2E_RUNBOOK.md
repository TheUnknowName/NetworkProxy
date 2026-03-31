# E2E Runbook

## Purpose
One-command validation for:
- TCP patch chain
- UDP patch chain
- CONNECT + TLS MITM chain
- Dynamic leaf certificate generation

## Command
```powershell
powershell -ExecutionPolicy Bypass -File .\tools\e2e_clean_validation.ps1
```

## Output
- Report file: `reports/e2e_validation_report.md`
- Runtime config: `config/proxy_e2e.yaml`

## Dependency
The TLS MITM and dynamic leaf certificate checks require `openssl`.
If `openssl` is not available, the script still validates TCP and UDP and marks TLS-related checks as `SKIP`.

## OpenSSL Install (Windows)
```powershell
winget install -e --id ShiningLight.OpenSSL.Light --accept-package-agreements --accept-source-agreements
```

## Re-run After OpenSSL
```powershell
powershell -ExecutionPolicy Bypass -File .\tools\e2e_clean_validation.ps1
Get-Content .\reports\e2e_validation_report.md
```
