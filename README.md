# Win32 AppWorkload Log Analyzer

A PowerShell-based tool for analyzing Microsoft Intune Win32 app deployment logs (`AppWorkload.log`) and generating interactive HTML reports.

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
