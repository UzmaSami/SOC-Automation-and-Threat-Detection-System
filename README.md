# ADSAE Custom PAM Tool

## Overview

This project documents the design,
development, and production deployment
of ADSAE — the Active Directory Security
Automation Engine — a custom PowerShell-
based security automation platform that
monitors Active Directory security events
every five minutes and automatically
remediates threats including brute force
attacks, privilege escalation attempts,
and suspicious PowerShell execution.

ADSAE runs in production on the Windows
Server 2022 Domain Controller documented
in Project 0. It has detected and
responded to real security threats. It
generates a live HTML security dashboard
that reflects the current security state
of the Active Directory environment. It
produces structured evidence logs that
feed the Sentinel SOC implemented in
Project 5.

Commercial Privileged Access Management
solutions — CyberArk, BeyondTrust,
Delinea — solve this problem at
enterprise scale at costs ranging from
tens of thousands to hundreds of thousands
of pounds per year. ADSAE solves it for
a specific environment at zero licensing
cost by replacing commercial tooling with
custom automation precisely calibrated
to the threats this environment faces.

---

## The Problem This Solves

Active Directory is the most targeted
asset in enterprise environments. The
reason is straightforward — it holds
the credentials and access rights for
every user and every system in the
domain. Compromising Active Directory
is not partial compromise of the
organisation. It is complete compromise.

The attack patterns targeting Active
Directory follow predictable sequences.
Brute force and password spray attacks
attempt to obtain valid credentials.
Once valid credentials are obtained the
adversary escalates privileges — adding
their account to Domain Admins or
creating a new privileged account. With
Domain Admin access the adversary can
move freely through the environment,
access any system, and maintain
persistence through mechanisms that
survive remediation attempts.

The window between initial credential
compromise and privilege escalation
is typically short. An adversary with
valid credentials who can reach a
Domain Controller can escalate privileges
in minutes. The security response must
therefore operate on the same timescale
— minutes, not hours. Human-operated
security processes that rely on an
analyst reading an alert and taking
action cannot reliably respond within
this window. Automated response can.

ADSAE closes this window by monitoring
the specific event log entries that
indicate these attack patterns and
executing remediation within minutes
of detection — faster than any human-
operated process and without requiring
analyst availability at any hour.

---

## Architecture


PRODUCTION ENVIRONMENT
════════════════════════════════════════════

Windows Server 2022 DC (UzmaSamiDC01)
- │
- ├── ADSAE CORE ENGINE
- │   └── ADSAE-Monitor.ps1
- │       Running as SYSTEM via Task Scheduler
- │       Execution interval: every 5 minutes
- │       Trigger: time-based + event-based
- │
- ├── DETECTION MODULES
- │   │
- │   ├── Module 1: Brute Force Detection
- │   │   Monitors: Event ID 4625
- │   │   Threshold: 5+ failures in 5 minutes
- │   │   Scope: per source IP + per target account
- │   │   Response: account disable + alert
- │   │
- │   ├── Module 2: Privilege Escalation Detection
- │   │   Monitors: Event ID 4728, 4732, 4756
- │   │   Scope: all privileged groups
- │   │   Protected groups:
- │   │     Domain Admins
- │   │     Enterprise Admins
- │   │     Schema Admins
- │   │     Administrators
- │   │     Group Policy Creator Owners
- │   │   Response: remove from group + alert
- │   │   Whitelist: approved admin accounts
- │   │
- │   └── Module 3: Suspicious PowerShell
- │       Monitors: Event ID 4104
- │       Detection: keyword pattern matching
- │       Keywords: encoded commands,
- │                 web downloads,
- │                 execution bypasses
- │       Response: evidence capture + alert
- │
- ├── RESPONSE ENGINE
- │   ├── Account disable (immediate)
- │   ├── Group membership removal (immediate)
- │   ├── Evidence capture (forensic preservation)
- │   ├── Alert generation (notification)
- │   └── Incident log creation (audit trail)
- │
- ├── EVIDENCE STORE
- │   └── C:\UzmaSOC-Logs\
- │       ├── incidents\
- │       │   └── [timestamped incident files]
- │       ├── evidence\
- │       │   └── [PowerShell script captures]
- │       └── adsae-audit.log
- │
- ├── DASHBOARD GENERATOR
- │   └── Live HTML dashboard
- │       Auto-refreshes every 5 minutes
- │       Shows: active threats, recent
- │       incidents, system status,
- │       detection statistics
- │
- └── AZURE SENTINEL INTEGRATION
    └── Events forwarded via
        Log Analytics Agent
        → Sentinel analytics rules
          reference ADSAE incident data


---

## Why Build This Rather Than Buy

The build versus buy question for
security tooling is genuinely complex
and the answer is not always build.
Commercial PAM solutions provide
capabilities that would take years
to replicate in custom tooling —
session recording, credential vaulting,
just-in-time access provisioning,
integration with enterprise ticketing
systems. For organisations at scale
with budget for commercial licensing
the buy answer is often correct.

For this environment the build answer
was correct for three reasons.

The first reason is precision. Commercial
PAM tools are designed to solve the
general PAM problem across a wide range
of environments and use cases. They
carry the complexity and configuration
overhead of that generality. ADSAE is
designed to solve the specific threat
patterns this specific environment faces.
Every detection threshold, every response
action, every whitelist entry is calibrated
to this environment. The result is a
tool with less noise and more relevant
signal than a general-purpose solution
would produce for the same scope.

The second reason is visibility. Using
commercial tooling produces a black box —
the tool detects threats and takes
actions through mechanisms the operator
cannot fully inspect. ADSAE is entirely
transparent — every detection decision,
every response action, every piece of
evidence collected is implemented in
readable PowerShell that can be
inspected, modified, and extended.
Understanding precisely what the tool
does and why is a security property
in itself.

The third reason is learning. Building
ADSAE required developing a detailed
understanding of Windows Security Event
Log structure, Active Directory API
operations, PowerShell automation
patterns, forensic evidence preservation,
and the specific techniques used in
Active Directory attacks. That
understanding cannot be acquired by
configuring a commercial tool. It can
only be acquired by building the
detection and response logic from first
principles.

---

## Detection Logic

### Brute Force Detection

Brute force and password spray attacks
leave a characteristic signature in
the Windows Security Event Log. Event
ID 4625 — an account failed to log on
— is generated every time an
authentication attempt fails. A single
failed logon for a legitimate user
forgetting their password generates
one or two events. A credential
stuffing attack against a user
generates dozens. A password spray
against an entire user population
generates hundreds across many accounts
from a single source IP.

The ADSAE brute force module monitors
Event ID 4625 using a rolling five-
minute window. It aggregates failures
by source IP address and by target
account separately — because spray
attacks distribute failures across
accounts while stuffing attacks
concentrate them on a single account.

powershell
function Invoke-BruteForceDetection {
    param(
        [int]$ThresholdMinutes = 5,
        [int]$ThresholdCount = 5
    )

    $startTime = (Get-Date).AddMinutes(
        -$ThresholdMinutes
    )

    # Query Security Event Log
    $failedLogons = Get-WinEvent -FilterHashtable @{
        LogName   = 'Security'
        Id        = 4625
        StartTime = $startTime
    } -ErrorAction SilentlyContinue

    if (!$failedLogons) { return }

    # Aggregate by source IP
    $bySourceIP = $failedLogons |
        ForEach-Object {
            $xml = \[xml\]$_.ToXml()
            [PSCustomObject]@{
                SourceIP    = $xml.Event.EventData.Data |
                    Where-Object {$_.Name -eq 'IpAddress'} |
                    Select-Object -ExpandProperty '#text'
                TargetUser  = $xml.Event.EventData.Data |
                    Where-Object {$_.Name -eq 'TargetUserName'} |
                    Select-Object -ExpandProperty '#text'
                TimeCreated = $_.TimeCreated
            }
        } |
        Group-Object SourceIP |
        Where-Object {$_.Count -ge $ThresholdCount}

    foreach ($group in $bySourceIP) {
        $affectedAccounts = $group.Group.TargetUser |
            Sort-Object -Unique

        # Execute response
        Invoke-BruteForceResponse `
            -SourceIP $group.Name `
            -AffectedAccounts $affectedAccounts `
            -FailureCount $group.Count
    }
}


When the threshold is crossed the
response module executes immediately.
Affected accounts that are not in the
protected whitelist are disabled in
Active Directory. An incident record
is created with the source IP, the
affected accounts, the failure count,
and the timestamp. The event is
forwarded to Sentinel.

The whitelist is critical. Disabling
accounts automatically without a
whitelist would disable service
accounts, administrative accounts,
and any other account that a
misconfigured application might
repeatedly fail to authenticate with.
The whitelist contains accounts that
should never be automatically disabled
regardless of the failure pattern —
specifically the service account used
by Azure AD Connect, the ADSAE service
account itself, and designated break-
glass accounts.

### Privilege Escalation Detection

Privileged group membership changes
are captured in Event ID 4728 — a
member was added to a security-enabled
global group. This event is generated
by Active Directory whenever any
account is added to any security group.
The ADSAE privilege escalation module
filters specifically for additions to
groups whose membership confers
dangerous capabilities.

powershell
function Invoke-PrivilegeEscalationDetection {

    $privilegedGroups = @(
        'Domain Admins',
        'Enterprise Admins',
        'Schema Admins',
        'Administrators',
        'Group Policy Creator Owners',
        'Account Operators',
        'Backup Operators'
    )

    # Protected accounts never removed
    $approvedAdmins = @(
        'Administrator',
        'uzma.admin',
        'svc-adsae'
    )

    $startTime = (Get-Date).AddMinutes(-5)

    $groupChanges = Get-WinEvent -FilterHashtable @{
        LogName   = 'Security'
        Id        = 4728
        StartTime = $startTime
    } -ErrorAction SilentlyContinue

    foreach ($event in $groupChanges) {
        $xml = \[xml\]$event.ToXml()

        $memberAdded = $xml.Event.EventData.Data |
            Where-Object {$_.Name -eq 'MemberName'} |
            Select-Object -ExpandProperty '#text'

        $targetGroup = $xml.Event.EventData.Data |
            Where-Object {$_.Name -eq 'TargetUserName'} |
            Select-Object -ExpandProperty '#text'

        $subjectUser = $xml.Event.EventData.Data |
            Where-Object {$_.Name -eq 'SubjectUserName'} |
            Select-Object -ExpandProperty '#text'

        # Only respond to privileged group changes
        if ($targetGroup -notin $privilegedGroups) {
            continue
        }

        # Extract account name from DN
        $accountName = ($memberAdded -split ',')[0] `
            -replace 'CN=', ''

        # Check against whitelist
        if ($accountName -in $approvedAdmins) {
            Write-AdsaeLog -Level INFO `
                -Message "Approved admin $accountName added to $targetGroup by $subjectUser — no action"
            continue
        }

        # Unauthorised escalation — respond
        Invoke-PrivEscResponse `
            -AccountName $accountName `
            -TargetGroup $targetGroup `
            -SubjectUser $subjectUser `
            -EventTime $event.TimeCreated
    }
}


The response removes the account from
the privileged group immediately. An
incident record is created capturing
the account that was added, the group
it was added to, the account that
performed the addition, and the time.
This incident record is the forensic
evidence that allows the investigation
to determine whether this was a
legitimate but unapproved change or
an adversarial privilege escalation.

The distinction between the account
that was added and the account that
performed the addition is significant.
In an adversarial scenario the subject
— the account that performed the
addition — may itself be compromised.
Investigating both the added account
and the subject account is standard
practice for privilege escalation
incidents.

### Suspicious PowerShell Detection

PowerShell is the most powerful
administrative tool available on
Windows and consequently one of the
most abused. Its ability to download
content from the internet, execute
code from memory without writing to
disk, and bypass script execution
policies makes it the tool of choice
for a large proportion of post-
exploitation activity.

Event ID 4104 — PowerShell script
block logging — captures the content
of PowerShell scripts as they execute
after any obfuscation has been decoded
by the PowerShell engine. This is
the key capability. An adversary who
base64 encodes a malicious command to
evade detection will find that script
block logging captures the decoded
version. The evasion technique that
works against command-line logging
does not work against script block
logging.

powershell
function Invoke-SuspiciousPowerShellDetection {

    $suspiciousPatterns = @(
        'Invoke-Expression',
        'IEX\(',
        'IEX \(',
        'DownloadString',
        'DownloadFile',
        'WebClient',
        'Net\.WebClient',
        'EncodedCommand',
        'enc ',
        'FromBase64String',
        '-ExecutionPolicy Bypass',
        '-ep bypass',
        'Hidden',
        'WindowStyle Hidden',
        'Start-Process.*-WindowStyle',
        'Invoke-Shellcode',
        'Invoke-Mimikatz',
        'Invoke-BloodHound',
        'PowerSploit',
        'Empire'
    )

    $startTime = (Get-Date).AddMinutes(-5)

    $psEvents = Get-WinEvent -FilterHashtable @{
        LogName      = 'Microsoft-Windows-PowerShell/Operational'
        Id           = 4104
        StartTime    = $startTime
    } -ErrorAction SilentlyContinue

    foreach ($event in $psEvents) {
        $scriptContent = $event.Message

        $detectedPatterns = $suspiciousPatterns |
            Where-Object {
                $scriptContent -match \[regex\]::Escape($_)
            }

        if ($detectedPatterns.Count -eq 0) {
            continue
        }

        # Capture evidence
        $evidencePath = "C:\UzmaSOC-Logs\evidence\" +
            "ps-$(Get-Date -Format 'yyyyMMdd-HHmmss').txt"

        @"
ADSAE POWERSHELL EVIDENCE CAPTURE
Time: $(Get-Date)
Patterns Detected: $($detectedPatterns -join ', ')
Script Content:
$scriptContent
"@ | Out-File $evidencePath -Encoding UTF8

        # Create incident
        New-AdsaeIncident `
            -Type 'SuspiciousPowerShell' `
            -Severity 'Medium' `
            -Details @{
                PatternsDetected = $detectedPatterns
                EvidencePath     = $evidencePath
                EventTime        = $event.TimeCreated
            }
    }
}


The PowerShell response is evidence
capture rather than automatic account
action. This is an intentional design
decision. PowerShell that matches
suspicious patterns is not necessarily
malicious — legitimate administrative
tools use encoded commands and web
downloads. Automatically disabling
the account of an administrator who
ran a legitimate script would cause
operational disruption without
security benefit.

The correct response to suspicious
PowerShell is preservation of evidence
and notification for human review.
The analyst who receives the alert
has the full script content available
immediately — not a vague alert
requiring them to search through event
logs to find the relevant entry. The
decision to act further — disable
the account, isolate the machine,
escalate the incident — is made by
the analyst with full context rather
than by the automation without it.

---

## Real Threats Detected in Production

ADSAE is not a theoretical tool.
It has detected and responded to
real security events on the production
Domain Controller.

### Brute Force Incident

A pattern of failed authentication
events triggered the brute force
module. Analysis of the incident
record showed a password spray
pattern — low failure count per
account, high failure count from a
single source IP, targeting many
accounts with common passwords.

ADSAE disabled the targeted accounts
within the five-minute detection
window. The Sentinel incident created
from the ADSAE log data provided
the full timeline and source
attribution for the post-incident
review. The accounts were re-enabled
after the source IP was blocked at
the network layer and password resets
were enforced.

### Privilege Escalation Incident

The privilege escalation module
triggered on an Event ID 4728 showing
an account being added to Domain
Admins by a subject account that was
not an approved administrator.

ADSAE removed the account from Domain
Admins within the five-minute detection
window. The incident record identified
both the added account and the subject
account — leading the investigation
to discover that the subject account
had been compromised during the
brute force attack that preceded
this incident. The attacker had
obtained credentials, used them to
add an account to Domain Admins, and
been automatically reversed before
they could use the elevated access.

### Suspicious PowerShell Incident

The PowerShell detection module
triggered on a script that contained
an encoded command and a web download
attempt. The evidence file captured
the full decoded script content —
a download cradle attempting to
retrieve a payload from an external
URL.

The evidence was submitted to threat
intelligence which confirmed the URL
as associated with known malware
infrastructure. The session was
terminated. The user account was
reviewed and found to have been
compromised through a phishing email
received earlier the same day.

---

## Live Dashboard

ADSAE generates a live HTML security
dashboard that provides real-time
visibility into the security state
of the Active Directory environment.

The dashboard refreshes automatically
every five minutes, aligned with the
ADSAE detection cycle. It displays
the current system status — whether
ADSAE is running, when it last
executed, and whether the last
execution produced any incidents.

The recent incidents panel shows
the last ten incidents with type,
severity, timestamp, and status.
Incidents are colour-coded by
severity — Critical in red, High
in orange, Medium in yellow —
allowing the analyst to identify
the priority items immediately.

The detection statistics panel shows
the cumulative counts of each
detection type — brute force
detections, privilege escalation
detections, PowerShell detections
— since ADSAE was deployed. This
trend data is more meaningful than
individual incident counts because
it shows whether the environment
is experiencing increasing or
decreasing threat activity over time.

The protected accounts panel shows
which accounts are in the disable
whitelist and which privileged group
members are in the approved admin
whitelist. This makes the whitelist
configuration visible in the
operational interface rather than
hidden in a configuration file.

---

## Integration with Sentinel

ADSAE and Sentinel are complementary
rather than redundant. They solve
different parts of the detection
and response problem.

Sentinel provides broad visibility
across all data sources — cloud
events, identity events, network
events, and on-premises events
through the Log Analytics agent.
Its analytics rules detect patterns
across the entire environment that
no single source could reveal. A
correlation between a suspicious
sign-in from Entra ID logs and an
anomalous process execution from
Security Event logs is something
Sentinel detects and ADSAE cannot.

ADSAE provides fast response to
the specific on-premises Active
Directory threats it is designed
to detect. Its five-minute execution
cycle means response to brute force
and privilege escalation happens
faster than any Sentinel analytics
rule to playbook to API call chain
could achieve.

The integration between them is
through the evidence logs that ADSAE
writes to C:\UzmaSOC-Logs\. These
logs are collected by the Log
Analytics agent installed through
Azure Arc and made available in
Sentinel. Analytics rules in Sentinel
can reference ADSAE incident data —
correlating an ADSAE brute force
detection with Entra ID sign-in
risk signals to produce a richer
incident record than either system
could produce alone.

---

## Challenges Encountered

*Task Scheduler reliability*

The ADSAE engine runs via Task
Scheduler. Early in the deployment
the task occasionally failed to
execute due to the service account
not having the required permissions
to query the Security Event Log.
Security Event Log access requires
the account to be a member of the
Event Log Readers group or to have
explicit read permissions on the
log file. Adding the service account
to Event Log Readers resolved the
execution failures.

This is a common oversight when
deploying scheduled tasks that query
security-relevant event logs — the
Security log is not readable by
standard users and the permission
requirement is not surfaced clearly
in the error messages when permission
is denied.

*Whitelist management*

The initial deployment without a
complete whitelist resulted in the
Azure AD Connect service account
being disabled by the brute force
module when it generated repeated
authentication failures due to an
expired password. The effect was
immediate — directory synchronisation
stopped and cloud-only changes ceased
to propagate to the on-premises
directory.

Recovery required re-enabling the
service account, updating its
password in Azure AD Connect, and
restarting the synchronisation
service. More importantly it required
updating the whitelist immediately
to prevent recurrence and prompted
a complete audit of all service
accounts that could generate
authentication patterns matching
the brute force threshold.

*Evidence log size management*

PowerShell script block events can
be large. The evidence capture for
suspicious PowerShell events can
produce multi-kilobyte files for
each detected event. Without log
management the evidence directory
grows without bound. A cleanup
routine was implemented that deletes
evidence files older than 90 days —
aligned with the Log Analytics
retention period so that evidence
is preserved for the investigation
window and then removed to prevent
indefinite growth.

---

## Lessons Learned

The most significant lesson from
building and operating ADSAE was
about the relationship between
automation and investigation.

Automated response is valuable
precisely because it operates faster
than human analysts. It is also
dangerous precisely because it
operates without human judgment.
The design decisions about which
responses are automated and which
require human review are the most
important design decisions in any
automated response system.

Account disable for brute force
victims is automated because the
risk of not acting — account
compromise — is immediate and
severe. Account disable for
suspicious PowerShell execution
is not automated because the risk
of false positive action — disabling
an administrator running a legitimate
script — is operationally significant
and the automated system cannot
distinguish the two cases reliably.

This calibration — what to automate
and what to surface for human review
— is a security engineering judgment
that no vendor tool can make for
a specific environment. It requires
understanding the specific threats,
the specific operational context,
and the specific consequences of
false positive and false negative
responses. Building ADSAE required
making these judgments explicitly
rather than accepting the defaults
of a commercial tool.

---

## What I Would Do Differently at Scale

At enterprise scale ADSAE's
architecture would change significantly.
The core detection logic — monitoring
specific event IDs and applying
thresholds — would remain valid but
the execution model would change from
a scheduled PowerShell script to an
Azure Function receiving events in
near-real-time through Event Hub.

Response actions would be executed
through the Microsoft Graph API and
Azure REST APIs rather than local
AD PowerShell — enabling response
to both cloud and on-premises identity
events from a single response platform.

The whitelist management would be
moved from a configuration file in
the script to a Key Vault backed
configuration — enabling whitelist
updates without modifying the script
and providing access-controlled,
audit-logged whitelist management.

The dashboard would be replaced by
a Sentinel workbook — integrating
ADSAE operational data with the
broader Sentinel SOC view rather
than maintaining a separate
operational interface.

---

## Series Navigation

| # | Project | Link |
|---|---------|------|
| ← P8 | Compliance & Governance | [View](../azure-compliance-governance) |
| *P9* | *ADSAE Security Tool* | You are here |
| → P10 | Landing Zone | [View](../azure-landing-zone) |
| 🏛️ | Enterprise Capstone | [View](../enterprise-hybrid-security-architecture) |

---

Uzma Shabbir
Azure Security Engineer | AZ-104 | AZ-500
[GitHub](https://github.com/UzmaSami) •
[LinkedIn](https://linkedin.com/in/uzma-shabbir-034361128)
