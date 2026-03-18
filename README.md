# Win32 AppWorkload Log Analyzer

A PowerShell-based tool for analyzing Microsoft Intune Win32 app deployment logs (`AppWorkload.log`) and generating interactive HTML reports.

## Features

- **CMTrace Log Parsing** — Parses standard SCCM/CMTrace format log entries
- **Multi-File Merging** — Automatically merges rotated log files in chronological order
- **App Inventory Extraction** — Extracts all assigned Win32 apps from the "Get policies" JSON
- **Per-App Event Tracking** — Tracks detection, applicability, download, install, and enforcement states for each app
- **ESP Phase Detection** — Identifies Autopilot Enrollment Status Page phases
- **Interactive HTML Report** — Generates a self-contained HTML report with:
  - Dashboard summary cards
  - Sortable/filterable app table
  - Expandable detail sections per app (commands, detection rules, timeline, errors)
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
2. **App Deployment Table** — Status, name, intent, target, detection, install result, enforcement state
3. **Expandable Details** — Install/uninstall commands, detection rules, install behavior, return codes, event timeline, error details
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
- Intune Management Extension (SideCar) Agent Logs

## License

MIT
