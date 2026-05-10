# Project-0B-SOC-Automation-and-Threat-Detection-System
## Project Overview
This project simulates a real-world Security Operations Center (SOC)
by detecting and responding to common cyber threats using Windows Event Logs and PowerShell automation. It identifies brure force login attempts, privilege escalation activities, suspicious PowerShell execution, and privileged account logins.
The system performs automated response actions such as disabling compromised accounts and removing unauthorized admin privileges. All events are exported to CSV and visualized through custom-built HTML dashboard with charts and metrics.
## Objectives 
Detect suspicious authentication activity

Automete incident response actions

Visualize security events in custom SOC dashboard
## Technologies Used
PowerShell

Windows Event Logs

Microsoft Sentinel (SIEM)

KQL (Kusto Query Language)

HTML + Chart.js (Dashboard Visualization)
## Detection Use Cases
### Brute Force Attack Detection
Event ID: 4625

Detection: Multiple failed login attempts

Response: Disable User Account

MITRE Mapping:

Tactic: Credential Access

Technique: T1110 - Brute Force
### Privilege Escalation Detection
Event ID: 4728

Detection: User Added to Domain Admins

Response: Remove user from Admin groups

MITRE Mapping:

Tactic: Privilege Escalation

Technique: T1078 - Valid Account
### Suspicious PowerShell Activity
Event ID: 4104

Detection: Use of IEX, DownloadString, EncodedCommand

Response: Log incident

MITRE Mapping

Tactic: Execution

Technique: T1059.001 -PowerShell
### Admin Login Monitoring
Event ID: 4672

Detection: Privileged account login

MITRE Mapping

Tactic: Privilege Escalation

Technique: T1068 - Exploitation for Privilege Escalation
## Automation Features
Real-time event monitoring

Automated account disabling

Automatic removal from privileged groups

Incident logging to file

Export of logs to CSV format
## Dashboard Features

HTML-based SOC dashboard

KPI metrics (attack counts)

Visual charts using Chart.js

Detailed event logs (tables)

## Project Structure
SOC-Automation-Projects/
|
|- scripts/
|    |-SOC-monitor.ps1
|    |-SOC-dashboard.ps1
|-logs/
|    |-bruteforce_logs.csv
|    |-privilege_logs.
|
|
      





