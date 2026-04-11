# Win32 AppWorkload Log Analyzer

A PowerShell-based toolkit for analyzing Microsoft Intune Management Extension (IME) logs and generating interactive HTML reports.

This repo contains **two independent analyzers**:

| Script | Log Source | Output |
|--------|-----------|--------|
| `Analyze-Win32AppWorkload.ps1` | `AppWorkload.log` | `Win32AppWorkload_Report.html` |
| `Analyze-IMEPowerShell.ps1` | `IntuneManagementExtension.log`, `AgentExecutor.log`, `HealthScripts.log` | `IME_PowerShell_Report.html` |

---

## Analyze-Win32AppWorkload.ps1

Analyzes Win32 and WinGet/Microsoft Store app deployments from `AppWorkload.log`.

Supports both traditional **Win32 apps** and **WinGet / Microsoft Store apps** deployed via Intune.

## Features

- **CMTrace Log Parsing** — Parses standard SCCM/CMTrace format log entries, including multi-line WinGet result blocks
- **Multi-File Merging** — Automatically merges rotated log files in chronological order
- **Cross-Session App Inventory** — Merges apps from all "Get policies" entries across check-in sessions, so apps from different sessions are never missed
- **WinGet / Microsoft Store App Support** — Automatically detects WinGet-type apps and extracts:
  - Package ID and source repository (e.g. `msstore`, `winget`)
  - WinGet operation result (`Ok`, `InstallError`, etc.)
  - Installed / detected version
  - Download progress, detection state, and applicability check results
- **Per-App Event Tracking** — Tracks detection, applicability, download, install, and enforcement states for each app
- **ESP Phase Detection** — Identifies Autopilot Enrollment Status Page phases
- **Interactive HTML Report** — Generates a self-contained HTML report with:
  - Dashboard summary cards
  - Sortable/filterable app table with **App Type** column (Win32 / WinGet)
  - Expandable detail sections per app (WinGet package info, commands, detection rules, timeline, errors)
  - Error summary section (general errors, deduplicated)
  - CSV export capability

## Usage

```powershell
# Analyze logs from a specific folder
.\Analyze-Win32AppWorkload.ps1 -LogFolder "C:\ProgramData\Microsoft\IntuneManagementExtension\Logs"

# Analyze specific log files
.\Analyze-Win32AppWorkload.ps1 -LogFiles "C:\Logs\AppWorkload.log","C:\Logs\AppWorkload-20260101-120000.log"

# Analyze and open report in browser
.\Analyze-Win32AppWorkload.ps1 -LogFolder "C:\Logs" -ShowInBrowser

# Specify custom output path
.\Analyze-Win32AppWorkload.ps1 -LogFolder "C:\Logs" -OutputPath "C:\Reports\MyReport.html"

# Run on an Intune-managed device (auto-discovers logs from default IME path)
.\Analyze-Win32AppWorkload.ps1
```

## Parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `-LogFiles` | string[] | No | One or more AppWorkload.log file paths |
| `-LogFolder` | string | No | Folder path to auto-discover all AppWorkload*.log files |
| `-OutputPath` | string | No | HTML report output path (default: same folder as logs) |
| `-ShowInBrowser` | switch | No | Auto-open report in default browser |

## Report Sections

1. **Summary Dashboard** — Total apps, installed, failed, pending, available counts
2. **App Deployment Table** — Status, name, **app type (Win32 / WinGet)**, intent, target, detection, install result, enforcement state
3. **Expandable Details**
   - *Win32 apps:* Install/uninstall commands, detection rules, install behavior, return codes
   - *WinGet apps:* Package ID, source repository, operation result, installed version
   - Event timeline and error details for all app types
4. **Error Summary** — General errors (non-app-specific), deduplicated
5. **Check-in Sessions** — Detected check-in sessions with timestamps

## Requirements

- PowerShell 5.1+ or PowerShell 7+
- No external modules required (fully self-contained)

---

## Analyze-IMEPowerShell.ps1

Analyzes PowerShell script and Proactive Remediation / HealthScript execution from IME logs.

### Features

- **Multi-File Merging** — Automatically merges rotated log files (`IntuneManagementExtension*.log`, `AgentExecutor*.log`, `HealthScripts*.log`) in chronological order
- **File-Lock Safe** — Reads live IME log files even while they are held open by the IME agent
- **PowerShell Script Runs** — Tracks each `[PowerShell]` polling cycle and per-policy script execution: context, download count, running mode, signature check, exit code, stderr length, result
- **Proactive Remediation / HealthScript Runs** — Tracks each HealthScript runner cycle with full detection → remediation → post-detection flow: pre-detect exit code, remediation triggered, post-detect result, output/error content
- **Script Body Display** — Reads detection and remediation script content from the IME HealthScript cache on disk and shows it inline in the report (for same-device analysis)
- **Deduplication** — Shows only the latest run per Policy ID, removing noise from repeated executions
- [Proactive Remediation / HealthScripts (Microsoft Learn)](https://learn.microsoft.com/en-us/intune/intune-service/fundamentals/remediations)
- **Cross-Correlation** — Matches AgentExecutor runs to PS script runs for complete exit code / stderr details
- **Interactive HTML Report** — Self-contained report with dashboard cards, sortable/filterable tables, and expandable per-policy detail rows showing script body, outputs, and errors

### Usage

```powershell
# Analyze from default IME log path (auto-discovers logs)
.\Analyze-IMEPowerShell.ps1

# Analyze from a specific folder and open in browser
.\Analyze-IMEPowerShell.ps1 -LogFolder "C:\ProgramData\Microsoft\IntuneManagementExtension\Logs" -ShowInBrowser

# Analyze specific log files
.\Analyze-IMEPowerShell.ps1 -LogFiles "C:\Logs\IntuneManagementExtension.log","C:\Logs\AgentExecutor.log","C:\Logs\HealthScripts.log"

# Specify custom output path
.\Analyze-IMEPowerShell.ps1 -LogFolder "C:\Logs" -OutputPath "C:\Reports\IME_Report.html"
```

### Parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `-LogFiles` | string[] | No | One or more IME log file paths |
| `-LogFolder` | string | No | Folder path to auto-discover all IME log files |
| `-OutputPath` | string | No | HTML report output path (default: same folder as logs, fallback to Downloads) |
| `-ShowInBrowser` | switch | No | Auto-open report in default browser |

### Report Sections

1. **Summary Dashboard** — Polling cycles, PS script runs (success/failed/max-retries), remediation runs (compliant/remediated/failed), log error count
2. **PowerShell Script Runs Table** — Per-policy execution with context, mode, exit code, stderr length, result; expandable detail with **script body**, command line, stdout/stderr
3. **Remediation / Proactive Remediation Table** — Per-policy run with schedule, pre-detect, remediation triggered, post-detect, result; expandable detail with **detection script body**, **remediation script body**, script outputs and errors
4. **Error Summary** — All CMTrace type-3 entries grouped by message (deduplicated)
5. **Polling Cycles** — IME PowerShell polling cycle timeline with script count per cycle

### Script Body Display

Proactive Remediation / HealthScript detection and remediation script bodies (`detect.ps1`, `remediate.ps1`) are stored by the IME agent in:

```
C:\Windows\IMECache\HealthScripts\{PolicyId}_{version}\detect.ps1
C:\Windows\IMECache\HealthScripts\{PolicyId}_{version}\remediate.ps1
```

**These files are owned by SYSTEM with no ACL entries for admins or regular users.**

- Script paths are always extracted from the log and shown in the report  
- Script body content is only readable when the analyzer runs **as SYSTEM** (e.g. via `PsExec -s`)  
- When running as a regular user or admin, the report shows the path with a note: *"Script body unavailable — IMECache files are SYSTEM-only"*

To run as SYSTEM with [PsExec](https://learn.microsoft.com/en-us/sysinternals/downloads/psexec):

```powershell
PsExec.exe -s -i powershell.exe -NoProfile -ExecutionPolicy Bypass -File C:\Path\To\Analyze-IMEPowerShell.ps1 -ShowInBrowser
```

---

## Requirements

- PowerShell 5.1+ or PowerShell 7+
- No external modules required (fully self-contained)

## Privacy & Data Handling

- This tool runs **locally only** — no data is sent to any external service.
- Log files may contain device names, user SIDs, app names, and other deployment metadata. **Do not share generated HTML reports publicly** without reviewing for sensitive information.
- The `.gitignore` excludes `*.log` and `*.html` files to prevent accidental commit of logs or reports containing PII.

## Disclaimer

This tool is provided as-is for troubleshooting purposes. It is not an official Microsoft product. Use at your own risk.

## References

- [Win32 app deployment flow (Microsoft Learn)](https://learn.microsoft.com/en-us/troubleshoot/mem/intune/app-management/develop-deliver-working-win32-app-via-intune)
- [WinGet app deployment via Intune (Microsoft Learn)](https://learn.microsoft.com/en-us/mem/intune/apps/store-apps-microsoft)
- Intune Management Extension (SideCar) Agent Logs

## License

MIT
