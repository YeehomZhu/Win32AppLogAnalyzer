<#
.SYNOPSIS
    IME PowerShell Script Log Analyzer - Parses Intune Management Extension logs and generates an HTML report.

.DESCRIPTION
    Analyzes IntuneManagementExtension.log, AgentExecutor.log, and HealthScripts.log to report on
    PowerShell script and Remediation/Proactive Remediation script execution from the Intune Management
    Extension (IME / SideCar agent).

    Output: IME_PowerShell_Report.html  (separate from the Win32/WinGet AppWorkload report)

.PARAMETER LogFiles
    One or more IME log file paths (IntuneManagementExtension*.log, AgentExecutor*.log, HealthScripts*.log).

.PARAMETER LogFolder
    Folder path to auto-discover all relevant IME log files.

.PARAMETER OutputPath
    Output path for the HTML report. Defaults to the same folder as the input logs.

.PARAMETER ShowInBrowser
    Auto-open the report in the default browser after generation.

.EXAMPLE
    .\Analyze-IMEPowerShell.ps1 -LogFolder "C:\ProgramData\Microsoft\IntuneManagementExtension\Logs" -ShowInBrowser
    .\Analyze-IMEPowerShell.ps1 -LogFiles "C:\Logs\IntuneManagementExtension.log","C:\Logs\AgentExecutor.log","C:\Logs\HealthScripts.log"
    .\Analyze-IMEPowerShell.ps1   # Auto-discovers from default IME log path
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string[]]$LogFiles,

    [Parameter(Mandatory = $false)]
    [string]$LogFolder,

    [Parameter(Mandatory = $false)]
    [string]$OutputPath,

    [Parameter(Mandatory = $false)]
    [switch]$ShowInBrowser
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Continue'

# ============================================================
# Section 1: Constants & Maps
# ============================================================

$HSResultMap = @{
    0 = 'Pending'
    1 = 'Failed'
    3 = 'Compliant'
    4 = 'Remediated'
    6 = 'Script Error'    # Script could not execute (ErrorCode set, outputs null)
}

$HSRemediationStatusMap = @{
    0 = 'Not Run'
    1 = 'Success'
    2 = 'Unknown'
    4 = 'Not Applicable'  # Device was already compliant; remediation script was not needed
}

$HSPolicyTypeMap = @{
    6  = 'Proactive Remediation'
    10 = 'Managed Installer'
}

# ============================================================
# Section 2: Log Parsing Helpers
# ============================================================

function Parse-CMTraceLog {
    param(
        [string[]]$LogContent,
        [string]$SourceFile = ''
    )

    $pattern = '<!\[LOG\[(?<Message>.*?)\]LOG\]!><time="(?<Time>[\d:.]+)" date="(?<Date>[\d-]+)" component="(?<Component>\w*)" context="(?<Context>[^"]*)" type="(?<Type>\d)" thread="(?<Thread>\d+)" file="(?<File>[^"]*)">'
    $results = [System.Collections.Generic.List[PSCustomObject]]::new()

    foreach ($line in $LogContent) {
        if ($line -match $pattern) {
            $dt = $null
            $dateStr = $Matches['Date']; $timeStr = $Matches['Time']
            try { $dt = [DateTime]::ParseExact("$dateStr $timeStr", 'M-d-yyyy HH:mm:ss.fffffff', $null) } catch {}
            if (-not $dt) { try { $dt = [DateTime]::ParseExact("$dateStr $timeStr", 'M-d-yyyy HH:mm:ss.fff', $null) } catch {} }
            if (-not $dt) { try { $dt = [DateTime]::Parse("$dateStr $timeStr") } catch { $dt = [DateTime]::MinValue } }

            $results.Add([PSCustomObject]@{
                Message    = $Matches['Message']
                DateTime   = $dt
                Component  = $Matches['Component']
                Type       = [int]$Matches['Type']
                Thread     = $Matches['Thread']
                SourceFile = $SourceFile
            })
        }
    }
    return $results.ToArray()
}

function Read-LogWithJoin {
    <# Reads a log file and joins multi-line CMTrace entries into single lines.
       Uses FileShare.ReadWrite so IME's currently-open log files can be read. #>
    param([string]$FilePath, [string]$Label = '')

    if ($Label) { Write-Host "    $Label" -ForegroundColor Cyan }

    $content = $null
    $stream  = $null
    $reader  = $null
    try {
        $stream  = [System.IO.File]::Open($FilePath, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
        $reader  = [System.IO.StreamReader]::new($stream, [System.Text.Encoding]::UTF8)
        $content = $reader.ReadToEnd()
    } finally {
        if ($reader) { $reader.Close() }
        if ($stream) { $stream.Close() }
    }
    $lines = $content -split "`r?`n"
    $merged  = [System.Collections.Generic.List[string]]::new()
    $buffer  = ''

    foreach ($l in $lines) {
        if (-not $l.Trim()) { continue }
        if ($l -match '^<!\[LOG\[') {
            $buffer = $l
        } elseif ($buffer) {
            $buffer += ' ' + $l.Trim()
        }
        if ($buffer -and $buffer -match '\]LOG\]!>') {
            $merged.Add($buffer)
            $buffer = ''
        }
    }
    if ($buffer) { $merged.Add($buffer) }
    return $merged.ToArray()
}

function Merge-LogFiles {
    <# Merges current + rotated log files of the same base name in chronological order. #>
    param([string[]]$FilePaths, [string]$LogBaseName)

    $current = $null
    $rotated = @()
    foreach ($fp in $FilePaths) {
        $name = [System.IO.Path]::GetFileNameWithoutExtension($fp)
        if ($name -match "^(.*_)?$([regex]::Escape($LogBaseName))$") {
            $current = $fp
        } else {
            $rotated += $fp
        }
    }

    $rotated = $rotated | Sort-Object {
        $n = [System.IO.Path]::GetFileNameWithoutExtension($_)
        if ($n -match '-(\d{8}-\d{6})') { $Matches[1] } else { $n }
    }

    $allLines = [System.Collections.Generic.List[string]]::new()
    foreach ($f in (@($rotated) + @($current) | Where-Object { $_ })) {
        $label = [System.IO.Path]::GetFileName($f)
        $lines = Read-LogWithJoin -FilePath $f -Label $label
        foreach ($l in $lines) { $allLines.Add($l) }
    }
    return $allLines.ToArray()
}

# ============================================================
# Section 3: Parse IntuneManagementExtension.log — PS Script Lifecycle
# ============================================================

function Parse-PSScriptRuns {
    param([PSCustomObject[]]$ImeEntries)

    $pollingCycles = [System.Collections.Generic.List[PSCustomObject]]::new()
    $scriptRuns    = [System.Collections.Generic.List[PSCustomObject]]::new()

    $currentCycle = $null
    $currentRun   = $null

    foreach ($e in ($ImeEntries | Sort-Object DateTime)) {
        $msg = $e.Message

        # ── Polling cycle boundaries ──────────────────────────────────────────
        if ($msg -match '\[PowerShell\] Polling thread starts') {
            $currentCycle = [PSCustomObject]@{
                StartTime    = $e.DateTime
                EndTime      = $null
                UserSessions = 0
                ScriptCount  = 0
            }
            $pollingCycles.Add($currentCycle)
            $currentRun = $null
            continue
        }

        if ($msg -match '\[PowerShell\] Polling thread stopped') {
            if ($currentCycle) { $currentCycle.EndTime = $e.DateTime }
            $currentRun = $null
            continue
        }

        if (-not $currentCycle) { continue }

        # ── Session info ──────────────────────────────────────────────────────
        if ($msg -match '\[PowerShell\] Get (\d+) active user sessions') {
            $currentCycle.UserSessions = [int]$Matches[1]
            continue
        }

        # ── Download count check (pre-run) ────────────────────────────────────
        if ($msg -match '\[PowerShell\] Policy ([\w-]+) for user ([\w-]+) has download count = (\d+)') {
            $polId = $Matches[1]; $userId = $Matches[2]; $dlCount = [int]$Matches[3]
            # Create placeholder so we can record MaxRetries even if processing never starts
            $exists = $scriptRuns | Where-Object {
                $_.PolicyId -eq $polId -and $_.CycleStart -eq $currentCycle.StartTime
            } | Select-Object -Last 1

            if (-not $exists) {
                $run = New-PSScriptRunObject -PolicyId $polId -UserId $userId -CycleStart $currentCycle.StartTime
                $run.DownloadCount = $dlCount
                if ($dlCount -ge 3) { $run.Result = 'MaxRetries' }
                $scriptRuns.Add($run)
                $currentCycle.ScriptCount++
            } else {
                $exists.DownloadCount = $dlCount
                if ($dlCount -ge 3) { $exists.Result = 'MaxRetries' }
            }
            continue
        }

        # ── Script processing start ───────────────────────────────────────────
        if ($msg -match '\[PowerShell\] Processing policy with id = ([\w-]+) for user ([\w-]+)') {
            $polId = $Matches[1]; $userId = $Matches[2]
            $currentRun = $scriptRuns | Where-Object {
                $_.PolicyId -eq $polId -and $_.CycleStart -eq $currentCycle.StartTime
            } | Select-Object -Last 1

            if (-not $currentRun) {
                $currentRun = New-PSScriptRunObject -PolicyId $polId -UserId $userId -CycleStart $currentCycle.StartTime
                $scriptRuns.Add($currentRun)
                $currentCycle.ScriptCount++
            }
            $currentRun.StartTime = $e.DateTime
            continue
        }

        if (-not $currentRun) { continue }

        # ── Per-policy properties ─────────────────────────────────────────────
        if      ($msg -match '\[PowerShell\] The policy needs be run as\s+(\S+)')      { $currentRun.ExecutionContext = $Matches[1] }
        elseif  ($msg -match 'PowerShell: Enforce signature check = (True|False)')     { $currentRun.SignatureCheck   = $Matches[1] }
        elseif  ($msg -match 'PowerShell: Running mode = (\d)')                        { $currentRun.RunningMode = if ($Matches[1] -eq '0') { '32-bit' } else { '64-bit' } }
        elseif  ($msg -match 'Launch powershell executor in (\w+) session')            { $currentRun.LaunchSession = $Matches[1] }
        elseif  ($msg -match 'Script file (.+\.ps1) is generated')                     { $currentRun.ScriptPath = $Matches[1] }

        # Result
        elseif ($msg -match '\[PowerShell\] User Id = ([\w-]+), Policy id = ([\w-]+), policy result = (\w+)') {
            $currentRun.Result       = $Matches[3]
            $currentRun.CompleteTime = $e.DateTime
            if ($Matches[3] -eq 'Failed' -or $e.Type -eq 3) { $currentRun.HasError = $true }
        }
        elseif ($msg -match '\[PowerShell\] Fail, the details are (.+)') {
            $currentRun.ErrorDetails = $Matches[1]
            $currentRun.HasError     = $true
        }
        elseif ($e.Type -eq 3 -and -not $currentRun.ErrorDetails) {
            $currentRun.ErrorDetails = $msg
            $currentRun.HasError     = $true
        }
    }

    return @{
        PollingCycles = $pollingCycles.ToArray()
        ScriptRuns    = $scriptRuns.ToArray()
    }
}

function New-PSScriptRunObject {
    param([string]$PolicyId, [string]$UserId, [DateTime]$CycleStart)
    return [PSCustomObject]@{
        PolicyId         = $PolicyId
        UserId           = $UserId
        CycleStart       = $CycleStart
        DownloadCount    = 0
        ExecutionContext  = $null
        SignatureCheck   = $null
        RunningMode      = $null
        LaunchSession    = $null
        StartTime        = $null
        CompleteTime     = $null
        Result           = 'Pending'
        ErrorDetails     = $null
        HasError         = $false
        ScriptPath       = $null
        ScriptBody       = $null
        # Populated later by correlation with AgentExecutor
        ExitCode         = $null
        StdOutLength     = $null
        StdErrLength     = $null
        StdErr           = $null
        StdOut           = $null
        CmdLine          = $null
    }
}

# ============================================================
# Section 4: Parse AgentExecutor.log
# ============================================================

function Parse-AgentExecutorRuns {
    param([PSCustomObject[]]$ExecEntries)

    $runs    = [System.Collections.Generic.List[PSCustomObject]]::new()
    $current = $null

    foreach ($e in ($ExecEntries | Sort-Object DateTime)) {
        $msg = $e.Message

        if ($msg -match 'ExecutorLog AgentExecutor gets invoked') {
            $current = [PSCustomObject]@{
                StartTime  = $e.DateTime
                EndTime    = $null
                ScriptType = $null     # 'powershell' | 'remediationScript' | 'powershellDetection'
                ScriptPath = $null
                CmdLine    = $null
                ProcessId  = $null
                ExitCode   = $null
                OutLength  = 0
                ErrLength  = 0
                StdErr     = $null
                StdOut     = $null
                Status     = 'Unknown'
            }
            $runs.Add($current)
            continue
        }

        if (-not $current) { continue }

        if      ($msg -match 'Adding argument (powershell|remediationScript|powershellDetection) with value (.+)') {
            $current.ScriptType = $Matches[1]
            $current.ScriptPath = $Matches[2].Trim()
        }
        elseif  ($msg -match 'cmd line for running powershell is (.+)')                 { $current.CmdLine = $Matches[1].Trim() }
        elseif  ($msg -match '\[Executor\] created powershell with process id (\d+)')   { $current.ProcessId = $Matches[1] }
        elseif  ($msg -match 'Powershell exit code is (\d+)')                           { $current.ExitCode = [int]$Matches[1] }
        elseif  ($msg -match 'length of out=(\d+)')                                     { $current.OutLength = [int]$Matches[1] }
        elseif  ($msg -match 'length of error=(\d+)')                                   { $current.ErrLength = [int]$Matches[1] }
        elseif  ($msg -match 'error from script = (.+)')                                { $current.StdErr = $Matches[1].Trim() }
        elseif  ($msg -match 'write output done\. output = (.+), error = (.+)') {
            $current.StdOut = $Matches[1].Trim()
            if (-not $current.StdErr -or $current.StdErr -eq '') { $current.StdErr = $Matches[2].Trim() }
        }
        elseif  ($msg -match 'Powershell script is (successfully executed|failed to execute)') {
            $current.Status = if ($Matches[1] -eq 'successfully executed') { 'Success' } else { 'Failed' }
        }
        elseif  ($msg -match 'Agent executor completed\.') {
            $current.EndTime = $e.DateTime
            $current = $null
        }
    }

    return $runs.ToArray()
}

# ============================================================
# Section 5: Parse HealthScripts.log — Remediation Script Flow
# ============================================================

function Parse-HealthScriptRuns {
    param([PSCustomObject[]]$HsEntries)

    $hsRuns         = [System.Collections.Generic.List[PSCustomObject]]::new()
    $schedTemplates = @{}   # PolicyId → @{ScheduleType; ScheduleInterval}
    $currentRun     = $null
    $runnerCycleId  = 0
    $detectCallIdx  = 0     # track pre vs post detection within one policy run

    foreach ($e in ($HsEntries | Sort-Object DateTime)) {
        $msg = $e.Message

        # ── Scheduler: capture schedule metadata ──────────────────────────────
        if ($msg -match '\[HS\].*inspect (daily|hourly|once|weekly) schedule for policy ([\w-]+).*Interval = (\d+)') {
            $schedTemplates[$Matches[2]] = @{
                ScheduleType     = $Matches[1]
                ScheduleInterval = [int]$Matches[3]
            }
            continue
        }

        # ── Runner: new cycle ─────────────────────────────────────────────────
        if ($msg -match '\[HS\] Runner.*Runner starts') {
            $runnerCycleId++
            $currentRun = $null
            continue
        }

        # ── New script processing ─────────────────────────────────────────────
        if ($msg -match '\[HS\] ProcessScript PolicyId: ([\w-]+) PolicyType: (\d+)') {
            $polId   = $Matches[1]
            $polType = [int]$Matches[2]

            $sched = if ($schedTemplates.ContainsKey($polId)) { $schedTemplates[$polId] } else { @{ ScheduleType = $null; ScheduleInterval = $null } }

            $currentRun = [PSCustomObject]@{
                PolicyId              = $polId
                PolicyType            = $polType
                PolicyTypeName        = if ($HSPolicyTypeMap.ContainsKey($polType)) { $HSPolicyTypeMap[$polType] } else { "Type $polType" }
                ScheduleType          = $sched['ScheduleType']
                ScheduleInterval      = $sched['ScheduleInterval']
                RunnerCycleId         = $runnerCycleId
                RunnerStartTime       = $e.DateTime
                PreDetectExitCode     = $null
                PreDetectCompliant    = $null
                RemediationTriggered  = $false
                RemediationExitCode   = $null
                PostDetectCompliant   = $null
                ResultCode            = $null
                ResultCodeName        = $null
                RemediationStatus     = $null
                RemediationStatusName = $null
                PreDetectOutput       = $null
                PreDetectError        = $null
                RemediationOutput     = $null
                RemediationError      = $null
                PostDetectOutput      = $null
                PostDetectError       = $null
                HasError              = $false
                CompletedTime         = $null
                DetectScriptPath      = $null
                DetectScriptBody      = $null
                RemediateScriptPath   = $null
                RemediateScriptBody   = $null
            }
            $hsRuns.Add($currentRun)
            $detectCallIdx = 0
            continue
        }

        if (-not $currentRun) { continue }

        # ── Script paths from agentexecutor command line ──────────────────────
        # Format: agentexecutor.exe -remediationScript ""detect.ps1""  or  ""remediate.ps1""
        if ($msg -match 'agentexecutor\.exe.*-remediationScript\s+""([^"]+\.ps1)""') {
            $scriptPath = $Matches[1]
            if ($scriptPath -match 'remedi') {
                if (-not $currentRun.RemediateScriptPath) { $currentRun.RemediateScriptPath = $scriptPath }
            } else {
                if (-not $currentRun.DetectScriptPath)    { $currentRun.DetectScriptPath    = $scriptPath }
            }
        }

        # ── Detection & remediation execution ─────────────────────────────────
        if ($msg -match '\[HS\] exit code of the script is (\d+)') {
            $detectCallIdx++
            if ($detectCallIdx -eq 1) { $currentRun.PreDetectExitCode = [int]$Matches[1] }
            # 2nd call is post-detection; don't overwrite pre-detect
        }
        elseif ($msg -match '\[HS\] the pre-remediation detection script compliance result for [\w-]+ is (True|False)') {
            $currentRun.PreDetectCompliant = $Matches[1]
        }
        elseif ($msg -match '\[HS\] remediation is not optional, kick off remediation') {
            $currentRun.RemediationTriggered = $true
        }
        elseif ($msg -match '\[HS\] remediation script exit code is (\d+)') {
            $currentRun.RemediationExitCode = [int]$Matches[1]
        }
        elseif ($msg -match '\[HS\] the post detection script result for [\w-]+ is (True|False)') {
            $currentRun.PostDetectCompliant = $Matches[1]
        }

        # ── Result JSON from service reporting ────────────────────────────────
        elseif ($msg -match '\[HS\] new result = (\{.+\})') {
            try {
                $j  = $Matches[1] | ConvertFrom-Json
                $rc = [int]$j.Result
                $rs = [int]$j.RemediationStatus

                $currentRun.ResultCode            = $rc
                $currentRun.ResultCodeName        = if ($HSResultMap.ContainsKey($rc)) { $HSResultMap[$rc] } else { "Code $rc" }
                $currentRun.RemediationStatus     = $rs
                $currentRun.RemediationStatusName = if ($HSRemediationStatusMap.ContainsKey($rs)) { $HSRemediationStatusMap[$rs] } else { "Status $rs" }
                $currentRun.PreDetectOutput       = $j.PreRemediationDetectScriptOutput
                $currentRun.PreDetectError        = $j.PreRemediationDetectScriptError
                $currentRun.RemediationOutput     = $j.RemediationScriptOutputDetails
                $currentRun.RemediationError      = $j.RemediationScriptErrorDetails
                $currentRun.PostDetectOutput      = $j.PostRemediationDetectScriptOutput
                $currentRun.PostDetectError       = $j.PostRemediationDetectScriptError
                $currentRun.CompletedTime         = $e.DateTime
                if ($rc -eq 1 -or $rs -eq 4) { $currentRun.HasError = $true }
            } catch {}
        }
    }

    return $hsRuns.ToArray()
}

# ============================================================
# Section 6: Correlate AgentExecutor → PS Script Runs
# ============================================================

function Correlate-ExecutorToPS {
    param(
        [PSCustomObject[]]$ScriptRuns,
        [PSCustomObject[]]$ExecutorRuns
    )

    # Only match 'powershell' type runs (not remediationScript or powershellDetection)
    $psExecRuns = @($ExecutorRuns | Where-Object { $_.ScriptType -eq 'powershell' })

    foreach ($sr in $ScriptRuns) {
        if (-not $sr.StartTime -or $sr.StartTime -eq [DateTime]::MinValue) { continue }

        $candidate = $psExecRuns | Where-Object {
            $_.StartTime -ge $sr.StartTime.AddSeconds(-5) -and
            $_.StartTime -le $sr.StartTime.AddSeconds(60)
        } | Sort-Object StartTime | Select-Object -First 1

        if ($candidate) {
            $sr.ExitCode     = $candidate.ExitCode
            $sr.StdOutLength = $candidate.OutLength
            $sr.StdErrLength = $candidate.ErrLength
            $sr.StdErr       = $candidate.StdErr
            $sr.StdOut       = $candidate.StdOut
            $sr.CmdLine      = $candidate.CmdLine

            # IME uses stderr presence (not exit code) to determine failure
            if ($sr.Result -eq 'Pending') {
                $sr.Result = if ($candidate.Status -eq 'Failed' -or
                                 ($candidate.StdErr -and $candidate.StdErr.Trim() -ne '')) {
                    'Failed'
                } else {
                    'Success'
                }
            }
        }
    }
}

# ============================================================
# Section 7: HTML Report Generation
# ============================================================

function Get-ReportCss {
    return @'
:root {
    --primary:#0078D4; --success:#107C10; --error:#D13438; --warning:#FFB900;
    --info:#00B7C3; --purple:#8764B8;
    --bg-secondary:#F3F2F1; --bg-card:#FFFFFF;
    --text-primary:#323130; --text-secondary:#605E5C; --border:#EDEBE9;
}
* { box-sizing:border-box; margin:0; padding:0; }
body { font-family:'Segoe UI',sans-serif; color:var(--text-primary); background:var(--bg-secondary); line-height:1.5; }
.container { max-width:1400px; margin:0 auto; padding:24px; }
.report-header { background:linear-gradient(135deg,#6B3FA0,#8764B8); color:white; padding:32px; border-radius:8px; margin-bottom:24px; }
.report-header h1 { font-size:24px; font-weight:600; margin-bottom:8px; }
.report-header .subtitle { font-size:14px; opacity:.9; }
.report-header .meta { font-size:12px; opacity:.8; margin-top:12px; }
.report-header .meta span { margin-right:20px; }
.dashboard { display:flex; flex-wrap:wrap; gap:16px; margin-bottom:24px; }
.card { background:var(--bg-card); border-radius:8px; padding:20px; flex:1; min-width:130px; box-shadow:0 1px 3px rgba(0,0,0,.1); border-top:4px solid var(--primary); text-align:center; }
.card .card-value { font-size:30px; font-weight:700; }
.card .card-label { font-size:11px; text-transform:uppercase; color:var(--text-secondary); margin-top:4px; letter-spacing:.5px; }
.card.success { border-top-color:var(--success); } .card.success .card-value { color:var(--success); }
.card.error   { border-top-color:var(--error);   } .card.error   .card-value { color:var(--error);   }
.card.warning { border-top-color:var(--warning); } .card.warning .card-value { color:var(--warning); }
.card.info    { border-top-color:var(--info);    } .card.info    .card-value { color:var(--info);    }
.card.purple  { border-top-color:var(--purple);  } .card.purple  .card-value { color:var(--purple);  }
.card.neutral { border-top-color:#8A8886;        } .card.neutral .card-value { color:#8A8886;        }
.section { background:var(--bg-card); border-radius:8px; margin-bottom:24px; box-shadow:0 1px 3px rgba(0,0,0,.1); overflow:hidden; }
.section-header { padding:16px 20px; font-size:18px; font-weight:600; border-bottom:1px solid var(--border); background:var(--bg-secondary); cursor:pointer; user-select:none; display:flex; justify-content:space-between; align-items:center; }
.section-header .toggle { font-size:14px; color:var(--text-secondary); }
.data-table { width:100%; border-collapse:collapse; font-size:13px; }
.data-table th { background:var(--bg-secondary); padding:10px 12px; text-align:left; font-weight:600; font-size:11px; text-transform:uppercase; letter-spacing:.5px; color:var(--text-secondary); border-bottom:2px solid var(--border); white-space:nowrap; cursor:pointer; user-select:none; }
.data-table th:hover { background:#E1DFDD; }
.data-table td { padding:9px 12px; border-bottom:1px solid var(--border); vertical-align:top; }
.data-table tr:hover { background:#F9F9F9; }
.data-table tr.clickable { cursor:pointer; }
.badge { display:inline-block; padding:2px 8px; border-radius:12px; font-size:11px; font-weight:600; text-transform:uppercase; letter-spacing:.3px; }
.badge-success     { background:#E8F5E9; color:var(--success); }
.badge-failed      { background:#FDE7E9; color:var(--error); }
.badge-pending     { background:#FFF8E1; color:#F57F17; }
.badge-maxretries  { background:#FCE4EC; color:#880E4F; }
.badge-compliant   { background:#E8F5E9; color:var(--success); }
.badge-remediated  { background:#E8F0FE; color:var(--primary); }
.badge-noncompliant{ background:#FFF3E0; color:#E65100; }
.badge-system      { background:#FFF3E0; color:#E65100; }
.badge-user-ctx    { background:#E8F5E9; color:#2E7D32; }
.badge-device      { background:#E3F2FD; color:#1565C0; }
.badge-info        { background:#E3F2FD; color:#1565C0; }
.badge-noactivity  { background:#F3F2F1; color:#8A8886; }
.badge-error       { background:#FDE7E9; color:var(--error); }
.detail-row { display:none; }
.detail-row.active { display:table-row; }
.detail-content { padding:16px 20px; background:#FAFAFA; }
.detail-content h4 { font-size:13px; font-weight:600; color:var(--primary); margin:10px 0 5px; }
.detail-content h4:first-child { margin-top:0; }
.code-block { background:#2D2D2D; color:#D4D4D4; padding:10px 12px; border-radius:4px; font-family:'Cascadia Code','Consolas',monospace; font-size:11px; overflow-x:auto; margin-bottom:8px; white-space:pre-wrap; word-break:break-all; max-height:200px; overflow-y:auto; }
.info-grid { display:grid; grid-template-columns:repeat(auto-fill,minmax(220px,1fr)); gap:6px; margin-bottom:8px; }
.info-item { display:flex; gap:8px; font-size:12px; }
.info-item .label { font-weight:600; color:var(--text-secondary); min-width:130px; }
.controls { background:var(--bg-card); border-radius:8px; padding:12px 16px; margin-bottom:16px; box-shadow:0 1px 3px rgba(0,0,0,.1); display:flex; flex-wrap:wrap; gap:10px; align-items:center; }
.controls input[type="text"] { padding:7px 10px; border:1px solid var(--border); border-radius:4px; font-size:13px; min-width:220px; }
.controls select { padding:7px 10px; border:1px solid var(--border); border-radius:4px; font-size:13px; background:white; }
.controls button { padding:7px 14px; border:1px solid var(--border); border-radius:4px; font-size:13px; background:white; cursor:pointer; }
.controls button:hover { background:var(--bg-secondary); }
.error-msg { color:var(--error); }
.font-mono { font-family:'Cascadia Code','Consolas',monospace; font-size:11px; }
.status-icon { text-align:center; width:32px; font-size:16px; }
.text-trunc { max-width:260px; overflow:hidden; text-overflow:ellipsis; white-space:nowrap; display:inline-block; vertical-align:middle; }
'@
}

function Get-ReportJS {
    return @'
function filterTable(tbodyId, searchId, statusId) {
    const q = (document.getElementById(searchId)?.value ?? '').toLowerCase();
    const s = document.getElementById(statusId)?.value ?? 'all';
    document.querySelectorAll('#' + tbodyId + ' tr.data-row').forEach(row => {
        const matchQ = !q || row.textContent.toLowerCase().includes(q);
        const matchS = s === 'all' || (row.getAttribute('data-status') ?? '') === s;
        row.style.display = matchQ && matchS ? '' : 'none';
        const det = document.getElementById('det-' + row.getAttribute('data-id'));
        if (det && (!matchQ || !matchS)) { det.classList.remove('active'); det.style.display = 'none'; }
    });
}
function toggleDetail(id) {
    const r = document.getElementById('det-' + id);
    if (r) { r.classList.toggle('active'); r.style.display = r.classList.contains('active') ? 'table-row' : 'none'; }
}
function toggleSection(id) {
    const c = document.getElementById(id);
    if (c) c.style.display = c.style.display === 'none' ? '' : 'none';
}
let sortDir = {};
function sortTable(tbodyId, col) {
    const tbody = document.getElementById(tbodyId);
    if (!tbody) return;
    const rows = Array.from(tbody.querySelectorAll('tr.data-row'));
    const key  = tbodyId + col;
    sortDir[key] = !sortDir[key];
    const dir = sortDir[key] ? 1 : -1;
    rows.sort((a, b) => {
        const av = a.cells[col]?.textContent.trim().toLowerCase() ?? '';
        const bv = b.cells[col]?.textContent.trim().toLowerCase() ?? '';
        if (!isNaN(av) && !isNaN(bv)) return (parseFloat(av) - parseFloat(bv)) * dir;
        return av.localeCompare(bv) * dir;
    });
    rows.forEach(row => {
        const det = document.getElementById('det-' + row.getAttribute('data-id'));
        tbody.appendChild(row);
        if (det) tbody.appendChild(det);
    });
}
'@
}

function HtmlEnc  { param([string]$s) [System.Web.HttpUtility]::HtmlEncode($s) }
function AttrEnc  { param([string]$s) [System.Web.HttpUtility]::HtmlAttributeEncode($s) }

function Generate-HtmlReport {
    param(
        [PSCustomObject[]]$ScriptRuns,
        [PSCustomObject[]]$HSRuns,
        [PSCustomObject[]]$PollingCycles,
        [PSCustomObject[]]$AllEntries,
        [string[]]$LogFileNames,
        [string]$DateRange
    )

    $css      = Get-ReportCss
    $js       = Get-ReportJS
    $genTime  = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $hostname = $env:COMPUTERNAME
    $logStr   = ($LogFileNames | ForEach-Object { HtmlEnc $_ }) -join ', '

    # ── Summary counts ────────────────────────────────────────────────────────
    $totalPS     = $ScriptRuns.Count
    $successPS   = @($ScriptRuns | Where-Object { $_.Result -eq 'Success' }).Count
    $failedPS    = @($ScriptRuns | Where-Object { $_.Result -eq 'Failed' }).Count
    $maxRetryPS  = @($ScriptRuns | Where-Object { $_.Result -eq 'MaxRetries' }).Count

    $totalHS      = $HSRuns.Count
    $compliantHS  = @($HSRuns | Where-Object { $_.ResultCode -eq 3 }).Count
    $remediatedHS = @($HSRuns | Where-Object { $_.ResultCode -eq 4 }).Count
    $failedHS     = @($HSRuns | Where-Object { $_.ResultCode -eq 1 -or $_.ResultCode -eq 6 }).Count
    $pendingHS    = @($HSRuns | Where-Object { $null -eq $_.ResultCode }).Count

    $totalCycles  = $PollingCycles.Count
    $errorCount   = @($AllEntries | Where-Object { $_.Type -eq 3 }).Count

    $html = @"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>IME PowerShell Script Analysis Report</title>
<style>$css</style>
</head>
<body>
<div class="container">

<div class="report-header">
    <h1>&#128196; IME PowerShell Script Analysis Report</h1>
    <div class="subtitle">Intune Management Extension — PowerShell &amp; Remediation / Proactive Remediation Scripts</div>
    <div class="meta">
        <span>&#128203; Host: $(HtmlEnc $hostname)</span>
        <span>&#128197; Generated: $genTime</span>
        <span>&#128196; Files: $logStr</span>
    </div>
    <div class="meta"><span>&#128197; Log Range: $(HtmlEnc $DateRange)</span></div>
</div>

<div class="dashboard">
    <div class="card info">   <div class="card-value">$totalCycles</div>  <div class="card-label">Polling Cycles</div></div>
    <div class="card info">   <div class="card-value">$totalPS</div>      <div class="card-label">PS Script Runs</div></div>
    <div class="card success"><div class="card-value">$successPS</div>    <div class="card-label">PS Success</div></div>
    <div class="card error">  <div class="card-value">$failedPS</div>     <div class="card-label">PS Failed</div></div>
    <div class="card warning"><div class="card-value">$maxRetryPS</div>   <div class="card-label">Max Retries</div></div>
    <div class="card purple"> <div class="card-value">$totalHS</div>      <div class="card-label">Remediation Runs</div></div>
    <div class="card success"><div class="card-value">$compliantHS</div>  <div class="card-label">Compliant</div></div>
    <div class="card info">   <div class="card-value">$remediatedHS</div> <div class="card-label">Remediated</div></div>
    <div class="card error">  <div class="card-value">$failedHS</div>     <div class="card-label">HS Failed</div></div>
    <div class="card neutral"><div class="card-value">$errorCount</div>   <div class="card-label">Log Errors</div></div>
</div>

"@

    # ════════════════════════════════════════════════════════════════════════════
    # PS Scripts Table
    # ════════════════════════════════════════════════════════════════════════════
    $html += @"
<div class="controls">
    <input type="text" id="psSearch" placeholder="&#128269; Search policy ID, user..." oninput="filterTable('psTbody','psSearch','psStatus')" />
    <select id="psStatus" onchange="filterTable('psTbody','psSearch','psStatus')">
        <option value="all">All Results</option>
        <option value="success">Success</option>
        <option value="failed">Failed</option>
        <option value="maxretries">Max Retries</option>
        <option value="pending">Pending</option>
    </select>
</div>
<div class="section">
    <div class="section-header" onclick="toggleSection('psSec')">
        PowerShell Script Runs ($totalPS)
        <span class="toggle">Click row to expand &#9660;</span>
    </div>
    <div id="psSec">
    <table class="data-table"><thead><tr>
        <th onclick="sortTable('psTbody',0)">&#11014;</th>
        <th onclick="sortTable('psTbody',1)">Start Time</th>
        <th onclick="sortTable('psTbody',2)">Policy ID</th>
        <th onclick="sortTable('psTbody',3)">Context</th>
        <th onclick="sortTable('psTbody',4)">DL#</th>
        <th onclick="sortTable('psTbody',5)">Run As</th>
        <th onclick="sortTable('psTbody',6)">Mode</th>
        <th onclick="sortTable('psTbody',7)">Sig Check</th>
        <th onclick="sortTable('psTbody',8)">Exit Code</th>
        <th onclick="sortTable('psTbody',9)">Stderr Len</th>
        <th onclick="sortTable('psTbody',10)">Result</th>
    </tr></thead>
    <tbody id="psTbody">
"@

    $psIdx = 0
    foreach ($sr in ($ScriptRuns | Sort-Object { if ($_.StartTime -and $_.StartTime -ne [DateTime]::MinValue) { $_.StartTime } else { [DateTime]::MaxValue } })) {
        $psIdx++
        $rowId = "ps$psIdx"

        $statusCss = switch ($sr.Result) {
            'Success'    { 'success' }
            'Failed'     { 'failed' }
            'MaxRetries' { 'maxretries' }
            default      { 'pending' }
        }
        $icon = switch ($sr.Result) {
            'Success'    { '&#9989;' }
            'Failed'     { '&#10060;' }
            'MaxRetries' { '&#9888;' }
            default      { '&#11036;' }
        }
        $resultBadge = "<span class=`"badge badge-$statusCss`">$(HtmlEnc $sr.Result)</span>"
        $timeStr  = if ($sr.StartTime -and $sr.StartTime -ne [DateTime]::MinValue) { $sr.StartTime.ToString('yyyy-MM-dd HH:mm:ss') } else { '-' }
        $polShort = if ($sr.PolicyId) { "$($sr.PolicyId.Substring(0,[Math]::Min(8,$sr.PolicyId.Length)))&#8230;" } else { '-' }

        $ctxBadge = if ($sr.UserId -and $sr.UserId -ne '00000000-0000-0000-0000-000000000000') {
            '<span class="badge badge-user-ctx">User</span>'
        } else {
            '<span class="badge badge-device">Device</span>'
        }
        $runAsBadge = if ($sr.ExecutionContext) {
            $cls = if ($sr.ExecutionContext -like '*System*') { 'badge-system' } else { 'badge-user-ctx' }
            "<span class=`"badge $cls`">$(HtmlEnc $sr.ExecutionContext)</span>"
        } else { '-' }
        $modeBadge = if ($sr.RunningMode)     { "<span class=`"badge badge-info`">$(HtmlEnc $sr.RunningMode)</span>" } else { '-' }
        $sigBadge  = if ($sr.SignatureCheck)  { "<span class=`"badge $(if ($sr.SignatureCheck -eq 'True') {'badge-system'} else {'badge-noactivity'})`">$(HtmlEnc $sr.SignatureCheck)</span>" } else { '-' }
        $dlBadge   = if ($sr.DownloadCount -ge 3) { "<span class=`"badge badge-maxretries`">$($sr.DownloadCount)</span>" }
                     elseif ($sr.DownloadCount -gt 0) { "<span class=`"badge badge-pending`">$($sr.DownloadCount)</span>" }
                     else { "<span class=`"badge badge-info`">0</span>" }
        $exitStr   = if ($null -ne $sr.ExitCode)     { "<span class=`"font-mono`">$($sr.ExitCode)</span>" } else { '-' }
        $stderrStr = if ($null -ne $sr.StdErrLength) {
            $cls = if ($sr.StdErrLength -gt 0) { ' error-msg' } else { '' }
            "<span class=`"font-mono$cls`">$($sr.StdErrLength)</span>"
        } else { '-' }

        $safePol = AttrEnc($sr.PolicyId)
        $html += @"
    <tr class="data-row clickable" data-id="$rowId" data-status="$statusCss" onclick="toggleDetail('$rowId')">
        <td class="status-icon">$icon</td>
        <td class="font-mono">$timeStr</td>
        <td title="$safePol" class="font-mono">$polShort</td>
        <td>$ctxBadge</td>
        <td>$dlBadge</td>
        <td>$runAsBadge</td>
        <td>$modeBadge</td>
        <td>$sigBadge</td>
        <td>$exitStr</td>
        <td>$stderrStr</td>
        <td>$resultBadge</td>
    </tr>
    <tr class="detail-row" id="det-$rowId">
        <td colspan="11">
            <div class="detail-content">
                <div class="info-grid">
                    <div class="info-item"><span class="label">Policy ID:</span>   <span class="value font-mono">$(HtmlEnc $sr.PolicyId)</span></div>
                    <div class="info-item"><span class="label">User ID:</span>      <span class="value font-mono">$(HtmlEnc $sr.UserId)</span></div>
                    <div class="info-item"><span class="label">Start Time:</span>   <span class="value">$timeStr</span></div>
                    <div class="info-item"><span class="label">Complete Time:</span><span class="value">$(if ($sr.CompleteTime -and $sr.CompleteTime -ne [DateTime]::MinValue){$sr.CompleteTime.ToString('yyyy-MM-dd HH:mm:ss')}else{'-'})</span></div>
                    <div class="info-item"><span class="label">Download Count:</span><span class="value">$($sr.DownloadCount)</span></div>
                    <div class="info-item"><span class="label">Exec Context:</span> <span class="value">$(HtmlEnc $sr.ExecutionContext)</span></div>
                    <div class="info-item"><span class="label">Running Mode:</span> <span class="value">$(HtmlEnc $sr.RunningMode)</span></div>
                    <div class="info-item"><span class="label">Sig. Check:</span>   <span class="value">$(HtmlEnc $sr.SignatureCheck)</span></div>
                    <div class="info-item"><span class="label">Launch Session:</span><span class="value">$(HtmlEnc $sr.LaunchSession)</span></div>
                    <div class="info-item"><span class="label">Exit Code:</span>    <span class="value font-mono">$(if ($null -ne $sr.ExitCode){$sr.ExitCode}else{'N/A'})</span></div>
                    <div class="info-item"><span class="label">Stdout Length:</span><span class="value">$(if ($null -ne $sr.StdOutLength){$sr.StdOutLength}else{'N/A'})</span></div>
                    <div class="info-item"><span class="label">Stderr Length:</span><span class="value$(if ($sr.StdErrLength -gt 0){' error-msg'})">$(if ($null -ne $sr.StdErrLength){$sr.StdErrLength}else{'N/A'})</span></div>
                </div>
"@
        $infoBlocks = @(
            @{ Label='Script Body';   Value=$sr.ScriptBody;    IsErr=$false },
            @{ Label='Script Path';   Value=$sr.ScriptPath;   IsErr=$false },
            @{ Label='Command Line';  Value=$sr.CmdLine;      IsErr=$false },
            @{ Label='Stderr Output'; Value=$sr.StdErr;       IsErr=$true  },
            @{ Label='Stdout Output'; Value=$sr.StdOut;       IsErr=$false },
            @{ Label='Error Details'; Value=$sr.ErrorDetails; IsErr=$true  }
        )
        foreach ($b in $infoBlocks) {
            if ($b.Value -and $b.Value.Trim() -ne '') {
                $style = if ($b.IsErr) { ' style="color:#F48771"' } else { '' }
                $html += "                <h4>$(HtmlEnc $b.Label)</h4><div class=`"code-block`"$style>$(HtmlEnc $b.Value)</div>`n"
            }
        }
        $html += "            </div></td></tr>`n"
    }

    $html += @"
    </tbody></table>
    </div>
</div>

"@

    # ════════════════════════════════════════════════════════════════════════════
    # Remediation Scripts Table
    # ════════════════════════════════════════════════════════════════════════════
    $html += @"
<div class="controls">
    <input type="text" id="hsSearch" placeholder="&#128269; Search policy ID..." oninput="filterTable('hsTbody','hsSearch','hsStatus')" />
    <select id="hsStatus" onchange="filterTable('hsTbody','hsSearch','hsStatus')">
        <option value="all">All Results</option>
        <option value="compliant">Compliant</option>
        <option value="remediated">Remediated</option>
        <option value="failed">Failed</option>
        <option value="pending">Pending</option>
    </select>
</div>
<div class="section">
    <div class="section-header" onclick="toggleSection('hsSec')">
        Remediation / Proactive Remediation Script Runs ($totalHS)
        <span class="toggle">Click row to expand &#9660;</span>
    </div>
    <div id="hsSec">
    <table class="data-table"><thead><tr>
        <th onclick="sortTable('hsTbody',0)">&#11014;</th>
        <th onclick="sortTable('hsTbody',1)">Run Time</th>
        <th onclick="sortTable('hsTbody',2)">Policy ID</th>
        <th onclick="sortTable('hsTbody',3)">Type</th>
        <th onclick="sortTable('hsTbody',4)">Schedule</th>
        <th onclick="sortTable('hsTbody',5)">Pre-Detect</th>
        <th onclick="sortTable('hsTbody',6)">Pre Exit</th>
        <th onclick="sortTable('hsTbody',7)">Remediated</th>
        <th onclick="sortTable('hsTbody',8)">Rem Exit</th>
        <th onclick="sortTable('hsTbody',9)">Post-Detect</th>
        <th onclick="sortTable('hsTbody',10)">Result</th>
    </tr></thead>
    <tbody id="hsTbody">
"@

    $hsIdx = 0
    foreach ($hs in ($HSRuns | Sort-Object { if ($_.RunnerStartTime -and $_.RunnerStartTime -ne [DateTime]::MinValue) { $_.RunnerStartTime } else { [DateTime]::MaxValue } })) {
        $hsIdx++
        $rowId = "hs$hsIdx"

        $statusCss = if     ($hs.ResultCode -eq 3)            { 'compliant'  }
                     elseif ($hs.ResultCode -eq 4)            { 'remediated' }
                     elseif ($hs.ResultCode -eq 1 -or $hs.ResultCode -eq 6) { 'failed' }
                     else                                     { 'pending'    }

        $icon        = switch ($statusCss) { 'compliant'{'&#9989;'} 'remediated'{'&#128295;'} 'failed'{'&#10060;'} default{'&#11036;'} }
        $resultName  = if ($hs.ResultCodeName) { $hs.ResultCodeName } else { 'Pending' }
        $resultBadge = "<span class=`"badge badge-$statusCss`">$(HtmlEnc $resultName)</span>"

        $timeStr     = if ($hs.RunnerStartTime -and $hs.RunnerStartTime -ne [DateTime]::MinValue) { $hs.RunnerStartTime.ToString('yyyy-MM-dd HH:mm:ss') } else { '-' }
        $polShort    = if ($hs.PolicyId) { "$($hs.PolicyId.Substring(0,[Math]::Min(8,$hs.PolicyId.Length)))&#8230;" } else { '-' }
        $typeStr     = if ($hs.PolicyTypeName) { "<span class=`"badge badge-info`">$(HtmlEnc $hs.PolicyTypeName)</span>" } else { '-' }
        $schedStr    = if ($hs.ScheduleType) { "$(HtmlEnc $hs.ScheduleType) / $($hs.ScheduleInterval)" } else { '-' }
        $preDetBadge = if     ($hs.PreDetectCompliant -eq 'True')  { '<span class="badge badge-compliant">Compliant</span>' }
                       elseif ($hs.PreDetectCompliant -eq 'False') { '<span class="badge badge-noncompliant">Non-Compliant</span>' }
                       else   { '-' }
        $postDetBadge= if     ($hs.PostDetectCompliant -eq 'True') { '<span class="badge badge-compliant">Compliant</span>' }
                       elseif ($hs.PostDetectCompliant -eq 'False'){ '<span class="badge badge-noncompliant">Non-Compliant</span>' }
                       else   { '-' }
        $remBadge    = if ($hs.RemediationTriggered) { '<span class="badge badge-remediated">Yes</span>' } else { '<span class="badge badge-noactivity">No</span>' }
        $preExitStr  = if ($null -ne $hs.PreDetectExitCode)    { "<span class=`"font-mono`">$($hs.PreDetectExitCode)</span>" }    else { '-' }
        $remExitStr  = if ($null -ne $hs.RemediationExitCode)  { "<span class=`"font-mono`">$($hs.RemediationExitCode)</span>" } else { '-' }
        $safePol     = AttrEnc($hs.PolicyId)

        $html += @"
    <tr class="data-row clickable" data-id="$rowId" data-status="$statusCss" onclick="toggleDetail('$rowId')">
        <td class="status-icon">$icon</td>
        <td class="font-mono">$timeStr</td>
        <td title="$safePol" class="font-mono">$polShort</td>
        <td>$typeStr</td>
        <td>$schedStr</td>
        <td>$preDetBadge</td>
        <td>$preExitStr</td>
        <td>$remBadge</td>
        <td>$remExitStr</td>
        <td>$postDetBadge</td>
        <td>$resultBadge</td>
    </tr>
    <tr class="detail-row" id="det-$rowId">
        <td colspan="11">
            <div class="detail-content">
                <div class="info-grid">
                    <div class="info-item"><span class="label">Policy ID:</span>           <span class="value font-mono">$(HtmlEnc $hs.PolicyId)</span></div>
                    <div class="info-item"><span class="label">Policy Type:</span>         <span class="value">$(HtmlEnc $hs.PolicyTypeName)</span></div>
                    <div class="info-item"><span class="label">Schedule:</span>            <span class="value">$(HtmlEnc "$($hs.ScheduleType) every $($hs.ScheduleInterval)")</span></div>
                    <div class="info-item"><span class="label">Run Time:</span>            <span class="value">$timeStr</span></div>
                    <div class="info-item"><span class="label">Complete Time:</span>       <span class="value">$(if ($hs.CompletedTime -and $hs.CompletedTime -ne [DateTime]::MinValue){$hs.CompletedTime.ToString('yyyy-MM-dd HH:mm:ss')}else{'-'})</span></div>
                    <div class="info-item"><span class="label">Result Code:</span>         <span class="value">$(HtmlEnc "$($hs.ResultCode) — $($hs.ResultCodeName)")</span></div>
                    <div class="info-item"><span class="label">Remediation Status:</span>  <span class="value">$(HtmlEnc "$($hs.RemediationStatus) — $($hs.RemediationStatusName)")</span></div>
                    <div class="info-item"><span class="label">Pre-Detect Exit:</span>     <span class="value font-mono">$(if ($null -ne $hs.PreDetectExitCode){$hs.PreDetectExitCode}else{'N/A'})</span></div>
                    <div class="info-item"><span class="label">Remediation Exit:</span>    <span class="value font-mono">$(if ($null -ne $hs.RemediationExitCode){$hs.RemediationExitCode}else{'N/A'})</span></div>
                    <div class="info-item"><span class="label">Pre-Detect Compliant:</span><span class="value">$(HtmlEnc $hs.PreDetectCompliant)</span></div>
                    <div class="info-item"><span class="label">Post-Detect Compliant:</span><span class="value">$(HtmlEnc $hs.PostDetectCompliant)</span></div>
                </div>
"@
        $outputBlocks = @(
            @{ L='Detection Script';      V=$(if ($hs.DetectScriptBody) { $hs.DetectScriptBody } elseif ($hs.DetectScriptPath) { "# Script body unavailable — IMECache files are SYSTEM-only.`n# Run this script as SYSTEM (e.g. PsExec -s) to include script content.`n# Path: $($hs.DetectScriptPath)" } else { $null }); E=$false },
            @{ L='Remediation Script';    V=$(if ($hs.RemediateScriptBody) { $hs.RemediateScriptBody } elseif ($hs.RemediateScriptPath) { "# Script body unavailable — IMECache files are SYSTEM-only.`n# Run this script as SYSTEM (e.g. PsExec -s) to include script content.`n# Path: $($hs.RemediateScriptPath)" } else { $null }); E=$false },
            @{ L='Pre-Detection Output';  V=$hs.PreDetectOutput;    E=$false },
            @{ L='Pre-Detection Error';   V=$hs.PreDetectError;     E=$true  },
            @{ L='Remediation Output';    V=$hs.RemediationOutput;  E=$false },
            @{ L='Remediation Error';     V=$hs.RemediationError;   E=$true  },
            @{ L='Post-Detection Output'; V=$hs.PostDetectOutput;   E=$false },
            @{ L='Post-Detection Error';  V=$hs.PostDetectError;    E=$true  }
        )
        foreach ($ob in $outputBlocks) {
            if ($ob.V -and $ob.V.Trim() -ne '') {
                $style = if ($ob.E) { ' style="color:#F48771"' } else { '' }
                $html += "                <h4>$(HtmlEnc $ob.L)</h4><div class=`"code-block`"$style>$(HtmlEnc $ob.V)</div>`n"
            }
        }
        $html += "            </div></td></tr>`n"
    }

    $html += @"
    </tbody></table>
    </div>
</div>

"@

    # ════════════════════════════════════════════════════════════════════════════
    # Error Summary
    # ════════════════════════════════════════════════════════════════════════════
    $errorEntries = @($AllEntries | Where-Object { $_.Type -eq 3 } | Sort-Object DateTime)
    if ($errorEntries.Count -gt 0) {
        $errGroups = $errorEntries |
            Group-Object { $_.Message.Substring(0, [Math]::Min(120, $_.Message.Length)) } |
            Sort-Object Count -Descending |
            Select-Object -First 40

        $html += @"
<div class="section">
    <div class="section-header" onclick="toggleSection('errSec')">
        Error Summary ($($errorEntries.Count) total, $($errGroups.Count) unique)
        <span class="toggle">Click to toggle</span>
    </div>
    <div id="errSec">
    <table class="data-table"><thead><tr>
        <th>Count</th><th>Last Seen</th><th>Source</th><th>Message</th>
    </tr></thead><tbody>
"@
        foreach ($g in $errGroups) {
            $last     = ($g.Group | Sort-Object DateTime | Select-Object -Last 1)
            $lastTime = if ($last.DateTime) { $last.DateTime.ToString('yyyy-MM-dd HH:mm:ss') } else { '' }
            $html += "    <tr><td>$($g.Count)</td><td class=`"font-mono`">$lastTime</td><td>$(HtmlEnc $last.SourceFile)</td><td class=`"error-msg`">$(HtmlEnc $last.Message)</td></tr>`n"
        }
        $html += "    </tbody></table></div></div>`n`n"
    }

    # ════════════════════════════════════════════════════════════════════════════
    # Polling Cycles
    # ════════════════════════════════════════════════════════════════════════════
    if ($PollingCycles.Count -gt 0) {
        $html += @"
<div class="section">
    <div class="section-header" onclick="toggleSection('cycleSec')">
        Polling Cycles ($($PollingCycles.Count))
        <span class="toggle">Click to toggle</span>
    </div>
    <div id="cycleSec" style="display:none">
    <table class="data-table"><thead><tr>
        <th>#</th><th>Start Time</th><th>End Time</th><th>Duration</th><th>User Sessions</th><th>Scripts Queued</th>
    </tr></thead><tbody>
"@
        $ci = 1
        foreach ($c in ($PollingCycles | Sort-Object StartTime)) {
            $cStart = if ($c.StartTime) { $c.StartTime.ToString('yyyy-MM-dd HH:mm:ss') } else { '-' }
            $cEnd   = if ($c.EndTime)   { $c.EndTime.ToString('yyyy-MM-dd HH:mm:ss') } else { '<em>Running…</em>' }
            $cDur   = if ($c.StartTime -and $c.EndTime -and $c.StartTime -ne [DateTime]::MinValue) {
                "$([int]($c.EndTime - $c.StartTime).TotalSeconds)s"
            } else { '-' }
            $html += "    <tr><td>$ci</td><td class=`"font-mono`">$cStart</td><td class=`"font-mono`">$cEnd</td><td>$cDur</td><td>$($c.UserSessions)</td><td>$($c.ScriptCount)</td></tr>`n"
            $ci++
        }
        $html += "    </tbody></table></div></div>`n`n"
    }

    # Footer
    $html += @"
<div style="text-align:center;padding:24px;color:var(--text-secondary);font-size:12px;">
    IME PowerShell Log Analyzer | Generated by PowerShell | $(Get-Date -Format 'yyyy')
</div>

</div>
<script>$js</script>
</body>
</html>
"@

    return $html
}

# ============================================================
# Section 8: Main Execution
# ============================================================

Add-Type -AssemblyName System.Web -ErrorAction SilentlyContinue

Write-Host ""
Write-Host "========================================" -ForegroundColor Magenta
Write-Host " IME PowerShell Script Log Analyzer" -ForegroundColor Magenta
Write-Host "========================================" -ForegroundColor Magenta
Write-Host ""

$defaultPath = "$env:ProgramData\Microsoft\IntuneManagementExtension\Logs"

# ── File discovery ────────────────────────────────────────────────────────────
$imeFiles  = @()
$execFiles = @()
$hsFiles   = @()
$outputDir = $null

if ($LogFiles) {
    foreach ($f in $LogFiles) {
        if (-not (Test-Path $f)) { Write-Warning "File not found: $f"; continue }
        $name = Split-Path $f -Leaf
        $resolved = (Resolve-Path $f).Path
        if      ($name -match 'IntuneManagementExtension') { $imeFiles  += $resolved }
        elseif  ($name -match 'AgentExecutor')             { $execFiles += $resolved }
        elseif  ($name -match 'HealthScripts')             { $hsFiles   += $resolved }
        else    { Write-Warning "Unrecognized log file name: $name (expected IntuneManagementExtension, AgentExecutor, or HealthScripts)" }
    }
    $outputDir = Split-Path $LogFiles[0] -Parent
}
elseif ($LogFolder) {
    if (-not (Test-Path $LogFolder)) { Write-Error "Folder not found: $LogFolder"; return }
    $imeFiles  = @(Get-ChildItem $LogFolder -File | Where-Object { $_.Name -match 'IntuneManagementExtension.*\.log$' } | Select-Object -ExpandProperty FullName)
    $execFiles = @(Get-ChildItem $LogFolder -File | Where-Object { $_.Name -match 'AgentExecutor.*\.log$'              } | Select-Object -ExpandProperty FullName)
    $hsFiles   = @(Get-ChildItem $LogFolder -File | Where-Object { $_.Name -match 'HealthScripts.*\.log$'              } | Select-Object -ExpandProperty FullName)
    $outputDir = $LogFolder
}
else {
    if (Test-Path $defaultPath) {
        $imeFiles  = @(Get-ChildItem $defaultPath -File | Where-Object { $_.Name -match 'IntuneManagementExtension.*\.log$' } | Select-Object -ExpandProperty FullName)
        $execFiles = @(Get-ChildItem $defaultPath -File | Where-Object { $_.Name -match 'AgentExecutor.*\.log$'              } | Select-Object -ExpandProperty FullName)
        $hsFiles   = @(Get-ChildItem $defaultPath -File | Where-Object { $_.Name -match 'HealthScripts.*\.log$'              } | Select-Object -ExpandProperty FullName)
        $outputDir = $defaultPath
        Write-Host "Auto-discovered from: $defaultPath" -ForegroundColor Green
    }
}

if ($imeFiles.Count -eq 0 -and $execFiles.Count -eq 0 -and $hsFiles.Count -eq 0) {
    Write-Host ""
    Write-Host "Usage:" -ForegroundColor Yellow
    Write-Host "  .\Analyze-IMEPowerShell.ps1 -LogFolder `"C:\ProgramData\Microsoft\IntuneManagementExtension\Logs`""
    Write-Host "  .\Analyze-IMEPowerShell.ps1 -LogFiles `"IntuneManagementExtension.log`",`"AgentExecutor.log`",`"HealthScripts.log`""
    Write-Host "  .\Analyze-IMEPowerShell.ps1   # auto-discovers from default IME log path"
    return
}

Write-Host "Discovered — IME: $($imeFiles.Count)  AgentExecutor: $($execFiles.Count)  HealthScripts: $($hsFiles.Count)" -ForegroundColor Cyan
Write-Host ""

# ── Read & parse ──────────────────────────────────────────────────────────────
$allEntries = [System.Collections.Generic.List[PSCustomObject]]::new()
$logNames   = @()

Write-Host "[Step 1/5] Reading and parsing log files..." -ForegroundColor Yellow

$imeEntries = @()
if ($imeFiles.Count -gt 0) {
    Write-Host "  IntuneManagementExtension:" -ForegroundColor Gray
    $lines = Merge-LogFiles -FilePaths $imeFiles -LogBaseName 'IntuneManagementExtension'
    $imeEntries = @(Parse-CMTraceLog -LogContent $lines -SourceFile 'IME.log')
    Write-Host "    $($imeEntries.Count) entries" -ForegroundColor Gray
    $logNames += $imeFiles | ForEach-Object { Split-Path $_ -Leaf }
    foreach ($e in $imeEntries) { $allEntries.Add($e) }
}

$execEntries = @()
if ($execFiles.Count -gt 0) {
    Write-Host "  AgentExecutor:" -ForegroundColor Gray
    $lines = Merge-LogFiles -FilePaths $execFiles -LogBaseName 'AgentExecutor'
    $execEntries = @(Parse-CMTraceLog -LogContent $lines -SourceFile 'AgentExecutor.log')
    Write-Host "    $($execEntries.Count) entries" -ForegroundColor Gray
    $logNames += $execFiles | ForEach-Object { Split-Path $_ -Leaf }
    foreach ($e in $execEntries) { $allEntries.Add($e) }
}

$hsEntries = @()
if ($hsFiles.Count -gt 0) {
    Write-Host "  HealthScripts:" -ForegroundColor Gray
    $lines = Merge-LogFiles -FilePaths $hsFiles -LogBaseName 'HealthScripts'
    $hsEntries = @(Parse-CMTraceLog -LogContent $lines -SourceFile 'HealthScripts.log')
    Write-Host "    $($hsEntries.Count) entries" -ForegroundColor Gray
    $logNames += $hsFiles | ForEach-Object { Split-Path $_ -Leaf }
    foreach ($e in $hsEntries) { $allEntries.Add($e) }
}

$sorted    = @($allEntries | Where-Object { $_.DateTime -ne [DateTime]::MinValue } | Sort-Object DateTime)
$dateRange = if ($sorted.Count -gt 0) {
    "$($sorted[0].DateTime.ToString('yyyy-MM-dd HH:mm:ss'))  ~  $($sorted[-1].DateTime.ToString('yyyy-MM-dd HH:mm:ss'))"
} else { 'N/A' }
Write-Host "  Total: $($allEntries.Count) entries | Range: $dateRange" -ForegroundColor Gray
Write-Host ""

# ── PS Script lifecycle ───────────────────────────────────────────────────────
Write-Host "[Step 2/5] Parsing PowerShell Script lifecycle (IME.log)..." -ForegroundColor Yellow
$psResult      = Parse-PSScriptRuns -ImeEntries $imeEntries
$scriptRuns    = $psResult.ScriptRuns
$pollingCycles = $psResult.PollingCycles
Write-Host "  Polling cycles: $($pollingCycles.Count) | Script runs: $($scriptRuns.Count)" -ForegroundColor Gray

# ── AgentExecutor ─────────────────────────────────────────────────────────────
Write-Host "[Step 3/5] Parsing AgentExecutor runs..." -ForegroundColor Yellow
$executorRuns = Parse-AgentExecutorRuns -ExecEntries $execEntries
Write-Host "  Executor runs: $($executorRuns.Count) (PS=$(@($executorRuns|Where-Object{$_.ScriptType -eq 'powershell'}).Count), Rem=$(@($executorRuns|Where-Object{$_.ScriptType -eq 'remediationScript'}).Count))" -ForegroundColor Gray

# ── HealthScripts ─────────────────────────────────────────────────────────────
Write-Host "[Step 4/5] Parsing HealthScript remediation runs..." -ForegroundColor Yellow
$hsRuns = Parse-HealthScriptRuns -HsEntries $hsEntries
# Keep only the latest run per PolicyId
$hsRuns = @($hsRuns | Group-Object PolicyId | ForEach-Object {
    $_.Group | Sort-Object { if ($_.RunnerStartTime -and $_.RunnerStartTime -ne [DateTime]::MinValue) { $_.RunnerStartTime } else { [DateTime]::MinValue } } | Select-Object -Last 1
})
Write-Host "  Remediation runs: $($hsRuns.Count) (deduplicated by PolicyId)" -ForegroundColor Gray

# ── Correlate executor → PS script runs ──────────────────────────────────────
Correlate-ExecutorToPS -ScriptRuns $scriptRuns -ExecutorRuns $executorRuns

# ── Read script bodies from disk ─────────────────────────────────────────────
# PS scripts: temp file paths captured during log parsing
foreach ($sr in $scriptRuns) {
    if ($sr.ScriptPath -and (Test-Path $sr.ScriptPath -ErrorAction SilentlyContinue)) {
        $sr.ScriptBody = Get-Content $sr.ScriptPath -Raw -ErrorAction SilentlyContinue
    }
}
# HS/Remediation scripts: use paths extracted from agentexecutor command lines in the log
# Note: IMECache files are owned by SYSTEM — readable only when this script runs as SYSTEM
$hsWithPath  = @($hsRuns | Where-Object { $_.DetectScriptPath -or $_.RemediateScriptPath })
foreach ($hs in $hsRuns) {
    if ($hs.DetectScriptPath -and -not $hs.DetectScriptBody) {
        $hs.DetectScriptBody = Get-Content $hs.DetectScriptPath -Raw -ErrorAction SilentlyContinue
    }
    if ($hs.RemediateScriptPath -and -not $hs.RemediateScriptBody) {
        $hs.RemediateScriptBody = Get-Content $hs.RemediateScriptPath -Raw -ErrorAction SilentlyContinue
    }
}
$hsWithBody = @($hsRuns | Where-Object { $_.DetectScriptBody -or $_.RemediateScriptBody })
if ($hsWithPath.Count -gt 0 -and $hsWithBody.Count -eq 0) {
    Write-Warning "Script bodies not readable: IMECache files are SYSTEM-only. Run this script as SYSTEM (e.g. via PsExec -s) to include script content in the report."
} elseif ($hsWithBody.Count -gt 0) {
    Write-Host "  Script bodies loaded: $($hsWithBody.Count) / $($hsWithPath.Count) policies" -ForegroundColor Green
}

$sSuccess  = @($scriptRuns | Where-Object { $_.Result -eq 'Success' }).Count
$sFailed   = @($scriptRuns | Where-Object { $_.Result -eq 'Failed' }).Count
$sRetries  = @($scriptRuns | Where-Object { $_.Result -eq 'MaxRetries' }).Count
$hsCompl   = @($hsRuns | Where-Object { $_.ResultCode -eq 3 }).Count
$hsRem     = @($hsRuns | Where-Object { $_.ResultCode -eq 4 }).Count
$hsFail    = @($hsRuns | Where-Object { $_.ResultCode -eq 1 -or $_.ResultCode -eq 6 }).Count
Write-Host "  PS: Success=$sSuccess | Failed=$sFailed | MaxRetries=$sRetries" -ForegroundColor $(if ($sFailed -gt 0) { 'Red' } else { 'Gray' })
Write-Host "  HS: Compliant=$hsCompl | Remediated=$hsRem | Failed=$hsFail" -ForegroundColor $(if ($hsFail -gt 0) { 'Red' } else { 'Gray' })

# ── Generate HTML ─────────────────────────────────────────────────────────────
Write-Host "[Step 5/5] Generating HTML report..." -ForegroundColor Yellow

$htmlContent = Generate-HtmlReport `
    -ScriptRuns    $scriptRuns `
    -HSRuns        $hsRuns `
    -PollingCycles $pollingCycles `
    -AllEntries    $allEntries.ToArray() `
    -LogFileNames  $logNames `
    -DateRange     $dateRange

# Output path
if (-not $OutputPath) { $OutputPath = Join-Path $outputDir 'IME_PowerShell_Report.html' }
if (Test-Path $OutputPath -PathType Container) { $OutputPath = Join-Path $OutputPath 'IME_PowerShell_Report.html' }
$outDir = Split-Path $OutputPath -Parent
if (-not (Test-Path $outDir)) { New-Item -ItemType Directory -Path $outDir -Force | Out-Null }

try {
    $htmlContent | Out-File -FilePath $OutputPath -Encoding UTF8 -Force -ErrorAction Stop
} catch {
    $fallback = Join-Path (Join-Path $env:USERPROFILE 'Downloads') 'IME_PowerShell_Report.html'
    Write-Warning "Cannot write to '$OutputPath'. Falling back to: $fallback"
    $htmlContent | Out-File -FilePath $fallback -Encoding UTF8 -Force
    $OutputPath = $fallback
}

Write-Host ""
Write-Host "Report generated successfully!" -ForegroundColor Green
Write-Host "  Output: $OutputPath" -ForegroundColor Cyan
Write-Host ""

if ($ShowInBrowser) {
    Write-Host "Opening in browser..." -ForegroundColor Gray
    Start-Process $OutputPath
}
