# ======================================================
# AD Security Automation Engine (ADSAE) v2.5 [MITRE Edition]
# ======================================================
# Author:      Uzma Sami
# Version:     2.5
# Date:        May 2026
# Description: Active Directory monitoring with MITRE ATT&CK Mapping
# Schedule:    Runs every 5 minutes via Task Scheduler
# Log Path:    C:\UzmaSOC-Logs\
# ======================================================

$Config = @{
    LogFolder            = "C:\UzmaSOC-Logs"
    IncidentLog          = "C:\UzmaSOC-Logs\incidents.txt"
    HTMLReport           = "C:\UzmaSOC-Logs\SOC-Dashboard.html"
    BruteForceThreshold  = 5
    BruteForceWindow     = 30
    PrivEscWindow        = 5
    PowerShellWindow     = 5
    WhitelistedAccounts  = @("Administrator","krbtgt","svc.aadconnect","svc.backup","Guest")
    WhitelistedAdmins    = @("Administrator","uzmasami.admin")
    SuspiciousKeywords   = @("Invoke-Expression","IEX","DownloadString","EncodedCommand","WebClient","bypass","AMSI","Mimikatz","-enc","hidden")
}

if (!(Test-Path $Config.LogFolder)) {
    New-Item -ItemType Directory -Path $Config.LogFolder -Force | Out-Null
}

$RunTime    = Get-Date
$RunTimeStr = $RunTime.ToString("yyyy-MM-dd HH:mm:ss")
$RunLog     = "$($Config.LogFolder)\run-$($RunTime.ToString('yyyyMMdd-HHmm')).txt"

$Script:BruteForceCount  = 0
$Script:PrivEscCount     = 0
$Script:PowerShellCount  = 0
$Script:TotalActions     = 0

function Write-Log {
    param([string]$Message, [string]$Level = "INFO", [string]$Category = "GENERAL", [string]$MitreID = "N/A")
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $icon = switch ($Level) { "INFO" {"[*]"} "WARN" {"[!]"} "ALERT" {"[ALERT]"} "ACTION" {"[SUCCESS]"} "ERROR" {"[ERROR]"} default {"[*]"} }
    
    $logLine = if ($MitreID -ne "N/A") {
        "$timestamp | $Level | $Category | [MITRE $MitreID] | $icon $Message"
    } else {
        "$timestamp | $Level | $Category | $icon $Message"
    }
    
    $color = switch ($Level) { "INFO" {"White"} "WARN" {"Yellow"} "ALERT" {"Red"} "ACTION" {"Green"} "ERROR" {"Red"} default {"White"} }
    Write-Host $logLine -ForegroundColor $color
    Add-Content -Path $RunLog -Value $logLine
    if ($Level -in @("ALERT", "ACTION", "ERROR")) { Add-Content -Path $Config.IncidentLog -Value $logLine }
}

function Write-SectionHeader {
    param([string]$Title)
    $line = "=" * 50
    Write-Host "`n$line`n  $Title`n$line" -ForegroundColor Cyan
    Add-Content -Path $RunLog -Value "`n$line`n  $Title`n$line"
}

Write-SectionHeader "SOC MONITOR STARTED WITH MITRE MAPPING -- $RunTimeStr"

# --- MODULE 1: BRUTE FORCE DETECTION ---
Write-SectionHeader "MODULE 1: BRUTE FORCE DETECTION"
$TimeWindow = $RunTime.AddMinutes(-$Config.BruteForceWindow)
try {
    $FailedLogins = Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4625; StartTime=$TimeWindow} -ErrorAction SilentlyContinue
    $eventCount = if ($FailedLogins) { $FailedLogins.Count } else {0}
    Write-Log "Total failed login events found: $eventCount" "INFO" "BRUTE-FORCE"
    $UserFailures = @{}
    foreach ($event in $FailedLogins) {
        $user = $event.Properties[5].Value
        if ([string]::IsNullOrWhiteSpace($user) -or $user -eq "-") {continue}
        if ($UserFailures.ContainsKey($user)) { $UserFailures[$user]++ } else { $UserFailures[$user] = 1 }
    }
    foreach ($user in $UserFailures.Keys) {
        $count = $UserFailures[$user]
        if ($count -ge $Config.BruteForceThreshold) {
            if ($Config.WhitelistedAccounts -contains $user) {
                Write-Log "WHITELISTED -- Skipping: $user ($count failures)" "WARN" "BRUTE-FORCE" "T1110"; continue
            }
            Write-Log "BRUTE FORCE DETECTED -- User: $user -- Failures: $count" "ALERT" "BRUTE-FORCE" "T1110"
            $Script:BruteForceCount++
            try {
                $adUser = Get-ADUser -Identity $user -Properties Enabled -ErrorAction Stop
                if ($adUser.Enabled) {
                    Disable-ADAccount -Identity $user -ErrorAction Stop
                    Write-Log "AUTO-RESPONSE: Account DISABLED -- $user" "ACTION" "BRUTE-FORCE" "T1110"
                    $Script:TotalActions++
                    $incident = "---INCIDENT---`nType: Brute Force Attack [MITRE T1110]`nTime: $RunTimeStr`nAccount: $user`nFailures: $count`nAction: Account Disabled`nStatus: REMEDIATED`n--------------"
                    Add-Content -Path $Config.IncidentLog -Value $incident
                } else {
                    Write-Log "Account already disabled: $user" "INFO" "BRUTE-FORCE" "T1110"
                }
            } catch {
                Write-Log "Error processing $user -- $_" "ERROR" "BRUTE-FORCE"
            }
        }
    }
} catch { Write-Log "Error reading Security log: $_" "ERROR" "BRUTE-FORCE" }

# --- MODULE 2: PRIVILEGE ESCALATION ---
Write-SectionHeader "MODULE 2: PRIVILEGE ESCALATION DETECTION"
$TimeWindow = $RunTime.AddMinutes(-$Config.PrivEscWindow)
try {
    $PrivEvents = Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4728; StartTime=$TimeWindow} -ErrorAction SilentlyContinue
    $privCount = if ($PrivEvents) {$PrivEvents.Count} else {0}
    foreach ($event in $PrivEvents) {
        $userAdded = $event.Properties[0].Value
        $addedBy   = $event.Properties[4].Value
        $groupName = $event.Properties[2].Value
        if ($groupName -like "Domain Admins" -or $groupName -like "Administrators") {
            if ($Config.WhitelistedAdmins -contains $userAdded) {
                Write-Log "WHITELISTED ADMIN -- Skipping: $userAdded" "WARN" "PRIV-ESC" "T1098"; continue
            }
            Write-Log "UNAUTHORIZED PRIV ESCALATION -- $userAdded added to $groupName" "ALERT" "PRIV-ESC" "T1098"
            $Script:PrivEscCount++
            try {
                Remove-ADGroupMember -Identity $groupName -Members $userAdded -Confirm:$false -ErrorAction Stop
                Write-Log "AUTO-RESPONSE: $userAdded REMOVED from $groupName" "ACTION" "PRIV-ESC" "T1098"
                $Script:TotalActions++
                $incident = "---INCIDENT---`nType: Unauthorized Priv Escalation [MITRE T1098]`nTime: $RunTimeStr`nAccount: $userAdded`nGroup: $groupName`nAction: Removed from group`nStatus: REMEDIATED`n--------------"
                Add-Content -Path $Config.IncidentLog -Value $incident
            } catch { Write-Log "Error removing $userAdded -- $_" "ERROR" "PRIV-ESC" }
        }
    }
} catch { Write-Log "Error reading privilege events: $_" "ERROR" "PRIV-ESC" }

# --- MODULE 3: SUSPICIOUS POWERSHELL ---
Write-SectionHeader "MODULE 3: SUSPICIOUS POWERSHELL DETECTION"
$TimeWindow = $RunTime.AddMinutes(-$Config.PowerShellWindow)
try {
    $PSEvents = Get-WinEvent -LogName "Microsoft-Windows-PowerShell/Operational" -ErrorAction SilentlyContinue |
        Where-Object { $_.Id -eq 4104 -and $_.TimeCreated -ge $TimeWindow }
    $psCount = if ($PSEvents) {$PSEvents.Count} else {0}
    foreach ($event in $PSEvents) {
        $message = $event.Message
        foreach ($keyword in $Config.SuspiciousKeywords) {
            if ($message -match [regex]::Escape($keyword)) {
                $riskLevel = switch ($keyword) { {$_ -in @("AMSI","Mimikatz")} {"CRITICAL"} {$_ -in @("IEX","EncodedCommand","-enc")} {"HIGH"} {$_ -in @("bypass","hidden")} {"HIGH"} default {"MEDIUM"} }
                Write-Log "SUSPICIOUS POWERSHELL [$riskLevel] -- Keyword: $keyword" "ALERT" "POWERSHELL" "T1059.001"
                $Script:PowerShellCount++
                $evidence = $message.Substring(0, [Math]::Min(500, $message.Length))
                $incident = "---INCIDENT---`nType: Suspicious PowerShell [MITRE T1059.001]`nTime: $RunTimeStr`nRisk: $riskLevel`nKeyword: $keyword`nEvidence: $evidence`nStatus: REQUIRES REVIEW`n--------------"
                Add-Content -Path $Config.IncidentLog -Value $incident
                $Script:TotalActions++
                break
            }
        }
    }
} catch { Write-Log "Error reading PowerShell logs: $_" "ERROR" "POWERSHELL" }

# --- MODULE 4: GENERATE HTML DASHBOARD ---
Write-SectionHeader "MODULE 4: GENERATING SOC DASHBOARD"
$incidentRows = ""
if (Test-Path $Config.IncidentLog) {
    $recentIncidents = Get-Content $Config.IncidentLog | Select-Object -Last 50
    foreach ($line in $recentIncidents) {
        if ($line -match "ALERT|ACTION|ERROR") {
            $rowClass = switch -Regex ($line) { "ALERT" {"row-alert"} "ACTION" {"row-action"} "ERROR" {"row-error"} default {"row-info"} }
            $incidentRows += "<tr class='$rowClass'><td>$line</td></tr>`n"
        }
    }
}
$bruteStatus = if ($Script:BruteForceCount -gt 0) { "<span class='badge-red'>MITRE T1110 - $($Script:BruteForceCount) Attacks</span>" } else { "<span class='badge-green'>Clear (T1110)</span>" }
$privStatus  = if ($Script:PrivEscCount -gt 0) { "<span class='badge-red'>MITRE T1098 - Escalation Blocked</span>" } else { "<span class='badge-green'>Clear (T1098)</span>" }
$psStatus    = if ($Script:PowerShellCount -gt 0) { "<span class='badge-yellow'>MITRE T1059.001 - Check Logs</span>" } else { "<span class='badge-green'>Clear (T1059.001)</span>" }

$html = @"
<!DOCTYPE html>
<html>
<head>
    <title>ADSAE MITRE SOC Dashboard</title>
    <meta http-equiv='refresh' content='300'>
    <style>
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body { font-family: 'Segoe UI', Arial; background: #0d1117; color: #e6edf3; padding: 30px; }
        .header { background: linear-gradient(135deg, #238636, #2ea44f); padding: 25px; border-radius: 12px; margin-bottom: 25px; }
        .header h1 { font-size: 24px; }
        .header p { opacity: 0.85; font-size: 13px; margin-top: 5px; }
        .metric-grid { display: grid; grid-template-columns: repeat(4,1fr); gap: 15px; margin-bottom: 25px; }
        .metric-box { background: #161b22; border: 1px solid #30363d; border-radius: 10px; padding: 20px; text-align: center; }
        .metric-number { font-size: 40px; font-weight: 700; }
        .metric-label { font-size: 12px; color: #8b949e; margin-top: 5px; }
        .num-red { color: #ff7b72; } .num-green { color: #3fb950; } .num-yellow { color: #e3b341; }
        .detection-grid { display: grid; grid-template-columns: repeat(3,1fr); gap: 15px; margin-bottom: 25px; }
        .detection-card { background: #161b22; border: 1px solid #30363d; border-radius: 10px; padding: 20px; }
        .detection-card h3 { font-size: 14px; color: #58a6ff; margin-bottom: 12px; }
        .detection-card p { font-size: 13px; color: #8b949e; margin: 5px 0; }
        h2 { color: #58a6ff; border-left: 4px solid #2ea44f; padding-left: 12px; margin: 25px 0 15px; font-size: 16px; }
        table { width: 100%; border-collapse: collapse; background: #161b22; border-radius: 10px; overflow: hidden; }
        th { background: #238636; color: white; padding: 10px; font-size: 12px; text-align: left; }
        td { padding: 8px 12px; font-size: 11px; font-family: monospace; border-bottom: 1px solid #21262d; }
        .row-alert { background: #2d0f0f; } .row-action { background: #0f2d1a; } .row-error { background: #2d1a0f; }
        .badge-green { background: #1a4731; color: #3fb950; padding: 3px 10px; border-radius: 20px; font-size: 12px; }
        .badge-red { background: #4d1919; color: #ff7b72; padding: 3px 10px; border-radius: 20px; font-size: 12px; }
        .badge-yellow { background: #3d2b00; color: #e3b341; padding: 3px 10px; border-radius: 20px; font-size: 12px; }
        footer { margin-top: 30px; text-align: center; color: #8b949e; font-size: 11px; }
    </style>
</head>
<body>
    <div class='header'>
        <h1>AD Security Automation Engine -- MITRE ATT&CK MATRIX STATUS</h1>
        <p>Author: Uzma Sami</p>
        <p>Last Analysis Run: $RunTimeStr</p>
    </div>
    <div class='metric-grid'>
        <div class='metric-box'><div class='metric-number num-red'>$($Script:BruteForceCount)</div><div class='metric-label'>T1110 - Brute Force</div></div>
        <div class='metric-box'><div class='metric-number num-red'>$($Script:PrivEscCount)</div><div class='metric-label'>T1098 - Account Manipulation</div></div>
        <div class='metric-box'><div class='metric-number num-yellow'>$($Script:PowerShellCount)</div><div class='metric-label'>T1059.001 - PowerShell Alerts</div></div>
        <div class='metric-box'><div class='metric-number num-green'>$($Script:TotalActions)</div><div class='metric-label'>Automated Remediations</div></div>
    </div>
    <div class='detection-grid'>
        <div class='detection-card'><h3>Credential Access</h3><p>Technique: Brute Force (T1110)</p><p>Status: $bruteStatus</p></div>
        <div class='detection-card'><h3>Privilege Escalation</h3><p>Technique: Account Manipulation (T1098)</p><p>Status: $privStatus</p></div>
        <div class='detection-card'><h3>Execution Engine</h3><p>Technique: PowerShell (T1059.001)</p><p>Status: $psStatus</p></div>
    </div>
    <h2>MITRE Targeted Incident Feed</h2>
    <table>
        <thead><tr><th>SIEM Audit Stream -- Last 50 Events Matched to MITRE ATT&CK Matrix</th></tr></thead>
        <tbody>$incidentRows</tbody>
    </table>
    <footer>AD Security Automation Engine v2.5 | MITRE Compliance Verification | Uzma Sami</footer>
</body>
</html>
"@

$html | Out-File $Config.HTMLReport -Encoding UTF8
Write-SectionHeader "EXECUTION SUMMARY"
Write-Log "=== SOC MONITOR COMPLETED WITH MITRE TAGS ===" "INFO" "SYSTEM"
