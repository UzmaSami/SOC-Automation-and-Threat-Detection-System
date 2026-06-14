# SOC-Automation-and-Threat-Detection-System
## Overview

This project documents the design and
operation of a production Microsoft
Sentinel Security Operations Centre
connected to a live Windows Server 2022
Domain Controller via Azure Arc — detecting,
investigating, and responding to real
security threats including brute force
attacks, privilege escalation attempts,
and suspicious PowerShell execution.

This is not a simulated environment.
The threats documented here were detected
on a production Domain Controller running
Active Directory. The alerts are real.
The incidents are real. The automated
responses are real.

Most security portfolios demonstrate
Sentinel configuration. This project
demonstrates Sentinel operation — the
difference between setting up a tool
and using it to detect and respond to
actual adversarial behaviour.

---

## The Problem This Solves

A Security Operations Centre exists to
answer one question continuously: is
something happening in our environment
right now that requires a response?

Answering that question requires three
capabilities working together. First,
visibility — the SOC must receive
telemetry from every asset in the
environment. Second, detection — the
SOC must have the analytical capability
to identify meaningful signals within
that telemetry and distinguish genuine
threats from background noise. Third,
response — when a threat is detected
the SOC must be able to act on it
quickly enough to prevent or limit
damage.

Most organisations that adopt Microsoft
Sentinel achieve the first capability
— they connect data sources and data
starts flowing. Many achieve partial
detection capability — they enable
built-in analytics rules and wait for
alerts. Very few achieve the third
capability — automated response that
operates faster than any human analyst
can.

This project implements all three for
a hybrid environment where the most
valuable and most targeted asset —
the Active Directory Domain Controller
— is on-premises, not in the cloud.

---

## Architecture


ON-PREMISES
═══════════════════════════════════════════
Windows Server 2022 DC (UzmaSamiDC01)
│
├── Windows Security Event Log
│   ├── Event 4624 — Successful logon
│   ├── Event 4625 — Failed logon
│   ├── Event 4648 — Explicit credential use
│   ├── Event 4672 — Special privilege logon
│   ├── Event 4688 — Process creation
│   ├── Event 4698 — Scheduled task created
│   ├── Event 4720 — User account created
│   ├── Event 4728 — Member added to group
│   ├── Event 4732 — Member added to group
│   └── Event 4104 — PowerShell script block
│
└── Azure Arc Agent (AMA)
    └── Data Collection Rule
        └── Streams events to ──────────────►
                                             │
AZURE                                        │
═══════════════════════════════════════════  │
Log Analytics Workspace ◄────────────────────┘
│
├── Raw event storage (90-day retention)
├── KQL query engine
└── Microsoft Sentinel
    │
    ├── DATA CONNECTORS
    │   ├── Windows Security Events via AMA
    │   ├── Microsoft Defender for Cloud
    │   ├── Azure Activity
    │   └── Azure AD Identity Protection
    │
    ├── ANALYTICS RULES (Custom)
    │   ├── Brute Force — 5+ failures in 5min
    │   ├── Privilege Escalation — Group 4728
    │   ├── Suspicious PowerShell — Event 4104
    │   ├── After Hours Admin Logon
    │   └── New Local Admin Account Created
    │
    ├── INCIDENTS
    │   ├── Real brute force detected ✅
    │   ├── Real priv escalation detected ✅
    │   └── Real PowerShell detected ✅
    │
    ├── AUTOMATION RULES
    │   ├── Auto-assign to analyst
    │   ├── Auto-tag by severity
    │   └── Trigger playbooks
    │
    └── PLAYBOOKS (Logic Apps)
        ├── Notify-On-Critical-Incident
        └── Enrich-Incident-With-IP-Info


---

## Why On-Premises DC as the Primary
## Data Source

The Domain Controller is the most
attacked asset in any Active Directory
environment. It holds the credentials
for every user in the organisation. It
controls authentication for every
resource on the domain. It stores
the Group Policy that governs the
security configuration of every domain-
joined machine. Compromise of the
Domain Controller is effectively
compromise of the entire organisation.

It is also the asset most frequently
excluded from cloud SIEM deployments.
Cloud-native SIEMs connect easily to
cloud services — Entra ID sign-in logs,
Azure Activity logs, Defender for Cloud
alerts all have native Sentinel
connectors that require minimal
configuration. On-premises Domain
Controllers require Arc connectivity,
Data Collection Rules, and careful
event filtering to collect the right
events without generating overwhelming
log volume.

This gap between what is easy to
connect and what is most important to
monitor is where real-world breaches
hide. An adversary who understands
Azure-focused SOC deployments will
target the on-premises environment
precisely because they know it is
less likely to be monitored with the
same rigour as cloud workloads.

Connecting the Domain Controller as
the primary Sentinel data source closes
this gap deliberately.

---

## Data Collection — Choosing the
## Right Events

Windows Security Event Log generates
thousands of events per day on an
active Domain Controller. Collecting
all of them creates log volume that
is expensive to store and impossible
to query efficiently. The discipline
of selecting the right events to
collect is as important as the
collection itself.

I implemented a Data Collection Rule
targeting the specific event IDs that
provide meaningful security signal
without collecting noise.

Authentication events — 4624, 4625,
4648, and 4768 — provide visibility
into who is authenticating, from where,
with what credentials, and whether they
are succeeding or failing. Failed
authentication events are the primary
signal for credential attack detection.

Privilege events — 4672, 4728, 4732,
4756, and 4769 — provide visibility
into sensitive group membership changes
and special privilege assignments.
An account being added to Domain Admins
is a high-value signal that should
generate an immediate alert regardless
of context. It may be legitimate. It
may be an attacker who has achieved
initial access and is escalating
privileges. Either way it requires
immediate investigation.

Process events — 4688 with command
line logging enabled — provide
visibility into what processes are
executing on the Domain Controller.
Legitimate administration generates
a predictable pattern of process
executions. Attackers use tools —
mimikatz, bloodhound, cobalt strike
— that generate process executions
that deviate from that pattern.

PowerShell script block logging —
event 4104 — captures the actual
content of PowerShell scripts as
they execute, after any obfuscation
has been decoded by the PowerShell
engine. An adversary who base64
encodes a malicious PowerShell command
to evade signature detection will
find that script block logging captures
the decoded command regardless of
the encoding technique used.

---

## Analytics Rules — Detection Logic

The built-in Sentinel analytics rules
provide broad coverage across common
attack patterns. They are a starting
point not an endpoint. The rules that
produce the most value for a specific
environment are those written for
that environment — rules that reflect
its specific users, systems, and
normal behaviour patterns.

I implemented five custom analytics
rules targeting the attack patterns
most relevant to an Active Directory
environment.

### Brute Force Detection

kql
SecurityEvent
| where EventID == 4625
| where TimeGenerated > ago(5m)
| summarize
    FailureCount = count(),
    TargetAccounts = make_set(TargetUserName),
    SourceIPs = make_set(IpAddress)
    by Computer, bin(TimeGenerated, 5m)
| where FailureCount >= 5
| extend
    AlertSeverity = iff(FailureCount >= 20,
        "High", "Medium"),
    Description = strcat(
        FailureCount,
        " failed logon attempts detected in 5 minutes"
    )


This rule detects credential stuffing
and password spray attacks by
identifying computers generating
five or more failed authentication
events within a five-minute window.
The threshold was calibrated against
the normal failure rate of the
environment — a threshold too low
generates false positives from
legitimate locked-out users. Too
high misses slow-and-low spray attacks.

### Privilege Escalation Detection

kql
SecurityEvent
| where EventID == 4728
| where TimeGenerated > ago(1h)
| where TargetUserName in (
    "Domain Admins",
    "Enterprise Admins",
    "Schema Admins",
    "Administrators",
    "Group Policy Creator Owners"
)
| project
    TimeGenerated,
    SubjectUserName,
    MemberName,
    TargetUserName,
    Computer
| extend
    AlertSeverity = "High",
    Description = strcat(
        MemberName,
        " was added to ",
        TargetUserName,
        " by ",
        SubjectUserName
    )


Any addition to a privileged group
generates a High severity alert
immediately. There is no threshold
here — a single event is sufficient
because legitimate privileged group
membership changes should be
infrequent, planned, and approved.
An alert for every change enforces
the expectation that every change
will be reviewed.

### Suspicious PowerShell Detection

kql
Event
| where EventID == 4104
| where Source == "Microsoft-Windows-PowerShell"
| where RenderedDescription has_any (
    "Invoke-Expression",
    "IEX",
    "DownloadString",
    "WebClient",
    "EncodedCommand",
    "FromBase64String",
    "Bypass",
    "Hidden",
    "-nop",
    "Net.WebClient"
)
| project
    TimeGenerated,
    Computer,
    RenderedDescription
| extend
    AlertSeverity = "Medium",
    Description = "Suspicious PowerShell
    execution technique detected"


This rule detects PowerShell
techniques commonly used in attacks —
encoded commands designed to evade
logging, web downloads that retrieve
payloads from external servers,
and execution policy bypass attempts.
Legitimate administrative scripts
rarely use these techniques. When
they do appear in a security-conscious
environment they warrant investigation
regardless of whether they prove
to be malicious.

---

## Real Threats Detected

This is where this project differs
from every tutorial and every lab
exercise. The analytics rules above
were not written to detect simulated
data. They detected real events on
a production Domain Controller.

### Incident 1 — Brute Force Attack

The brute force analytics rule
triggered against a pattern of
failed authentication events
targeting multiple user accounts
from a single source in a short
time window. The event data showed
a classic password spray pattern —
one or two attempts per account
across many accounts, staying below
per-account lockout thresholds while
testing a common password across
the user population.

Investigation confirmed the attempts
were not from any authorised source.
The ADSAE automation engine — built
in Project 9 — detected the same
pattern independently through its
own monitoring of Event 4625 and
disabled the targeted accounts
automatically before any successful
authentication occurred.

This incident validated the layered
detection approach — Sentinel
provided visibility and an incident
record for investigation while ADSAE
provided the automated response.
Neither system alone provides what
both together achieve.

### Incident 2 — Privilege Escalation

The privilege escalation analytics
rule triggered on an Event 4728
showing an account being added to
the Domain Admins group. The
SubjectUserName — the account that
performed the addition — was not
an account with a legitimate
administrative function.

Investigation revealed the account
had been used in the brute force
attempt from Incident 1 and had
successfully authenticated during
a window before the brute force
rule triggered. The attacker had
obtained access and immediately
attempted privilege escalation.

The ADSAE engine removed the account
from Domain Admins automatically
on detecting Event 4728. The Sentinel
incident provided the timeline and
the full context of how the initial
access was obtained — information
that would not have been available
if only the escalation had been
detected without the preceding
authentication events.

### Incident 3 — Suspicious PowerShell

The PowerShell analytics rule
triggered on Event 4104 showing
execution of a script containing
an encoded command and a web
download attempt. The script
attempted to download content
from an external URL using
System.Net.WebClient.

The ADSAE engine captured the
full script content as evidence.
The external URL was submitted
to threat intelligence and
confirmed as associated with
a known malware distribution
infrastructure.

This incident demonstrated the
value of PowerShell script block
logging specifically — the command
was base64 encoded and would not
have been detected by signature-
based tools inspecting the raw
command line. Script block logging
captures the decoded execution
content regardless of encoding.

---

## Incident Response Workflow

Each detected incident followed
a documented response workflow
that provides consistency and
ensures no investigation steps
are skipped regardless of the
time of day the incident is
detected.


DETECTION
- │
- ├── Analytics rule fires
- ├── Incident created in Sentinel
- ├── Automation rule assigns incident
- └── Notification sent via playbook
  -       │
   -      ▼
- TRIAGE (within 15 minutes)
- │
- ├── Severity assessment
- ├── Affected assets identified
- ├── Initial scope determination
- └── Escalation decision
  -       │
   -      ▼
INVESTIGATION
- │
- ├── Timeline reconstruction via KQL
- ├── Related events correlated
- ├── Threat intelligence lookup
- └── Root cause identified
-         │
 -        ▼
CONTAINMENT
- │
- ├── ADSAE automated response (immediate)
- ├── Account disable if compromised
- ├── Network isolation if required
- └── Evidence preservation
  -       │
   -      ▼
ERADICATION AND RECOVERY
- │
- ├── Malicious changes reversed
- ├── Affected accounts remediated
- ├── Access reviewed and tightened
- └── Vulnerability addressed
  -       │
   -      ▼
POST-INCIDENT
- │
- ├── Incident documented in Sentinel
- ├── Analytics rule tuned if needed
- ├── ADSAE playbook updated if needed
- └── Lessons incorporated


---

## KQL Threat Hunting

Beyond reactive detection through
analytics rules I implemented proactive
threat hunting queries that run against
historical data to identify patterns
that may indicate compromise that has
not yet triggered an alert.

### Hunt for Lateral Movement

kql
SecurityEvent
| where EventID == 4624
| where LogonType == 3
| where TimeGenerated > ago(7d)
| summarize
    UniqueSourceIPs = dcount(IpAddress),
    LogonCount = count(),
    TargetAccounts = make_set(TargetUserName)
    by SubjectUserName
| where UniqueSourceIPs > 3
| where LogonCount > 20
| order by UniqueSourceIPs desc


This query identifies accounts
authenticating from an unusual number
of source IPs in a seven-day window
— a pattern consistent with credential
use across multiple systems that may
indicate lateral movement.

### Hunt for Persistence Mechanisms

kql
SecurityEvent
| where EventID == 4698
| where TimeGenerated > ago(24h)
| project
    TimeGenerated,
    SubjectUserName,
    TaskName,
    TaskContent,
    Computer
| where SubjectUserName !endswith "$"
| order by TimeGenerated desc


Scheduled task creation is a common
persistence mechanism. This query
identifies scheduled tasks created
by non-machine accounts in the last
24 hours — a pattern that warrants
review to confirm legitimacy.

---

## Playbook — Automated Enrichment

The incident enrichment playbook
runs automatically when a High
severity incident is created. It
extracts IP addresses from the
incident and queries a threat
intelligence API for context —
country of origin, known malicious
activity, ASN information — and
adds this information to the
incident as a comment.

This enrichment happens in seconds,
providing the analyst who opens
the incident with context that
would otherwise require manual
lookup against multiple sources.
The analyst begins investigation
with information rather than
beginning investigation by gathering
information.

---

## Challenges Encountered

**Data Collection Rule configuration
for Arc-connected servers**

The legacy method of connecting on-
premises servers to Sentinel used
the Microsoft Monitoring Agent with
workspace-level configuration. The
current method uses the Azure
Monitoring Agent with Data Collection
Rules. The two methods collect events
differently and cannot run
simultaneously on the same server.

The decision to use AMA with Data
Collection Rules was deliberate —
it aligns with Microsoft's current
architecture and avoids a future
migration. The challenge was that
some Sentinel data connector
documentation still references the
MMA method. Navigating between
current and legacy documentation
to implement the correct architecture
required careful attention to
publication dates and version
references.

*Analytics rule tuning*

The initial brute force threshold
of five failures in five minutes
generated significant false positive
volume from a service account that
was misconfigured and repeatedly
attempting to authenticate with
an expired password. Rather than
raising the threshold — which would
have reduced detection sensitivity
— I added an exclusion for the
specific service account and created
a separate lower-priority alert
for that account's authentication
failures to ensure the underlying
misconfiguration was addressed.

This is the reality of production
SOC operation. Tuning is continuous.
Rules that generate noise are not
disabled — they are refined. The
goal is high-fidelity alerting, not
silence.

*Incident volume management*

Three active analytics rules on a
production Domain Controller generate
meaningful incident volume. Managing
this volume without allowing genuine
threats to be lost in noise required
implementing incident grouping —
configuring rules to group related
events into a single incident rather
than creating a separate incident
for every event that matches the
rule criteria. A brute force attack
generating fifty failed logon events
creates one incident, not fifty.

---

## Lessons Learned

The most important lesson from
operating this SOC was that detection
without response is notification
without action. An analytics rule
that fires and creates an incident
has provided awareness. Awareness
without response is insufficient —
an adversary continues operating
while the incident sits in the queue
waiting for an analyst.

The integration between Sentinel
detection and ADSAE automated
response — described in Project 9
— is the answer to this problem
in this environment. For larger
environments the answer is a full
SOAR implementation using Sentinel
playbooks to execute response actions
automatically. The principle is the
same regardless of scale: detection
and response must be coupled, not
sequential.

The second lesson was about the
value of real data. Every tutorial
on Sentinel analytics rules uses
sample data or generated test events.
Operating against real Domain
Controller events surfaces issues
that sample data never reveals —
legitimate processes that match
detection signatures, service accounts
with authentication patterns that
look malicious, scheduled tasks
created by monitoring tools that
appear in persistence hunting queries.
Tuning a rule against real data is
a fundamentally different and more
valuable experience than writing
a rule against synthetic data.

---

## What I Would Do Differently at Scale

At enterprise scale I would implement
the Sentinel SOC with dedicated tiers —
Level 1 analysts for triage and initial
response, Level 2 for investigation,
and Level 3 for threat hunting and
rule development. The playbooks would
be significantly more extensive,
covering automated containment actions
including isolating endpoints through
Defender for Endpoint, disabling
accounts through Graph API, and
creating firewall rules to block
malicious IPs.

UEBA — User and Entity Behaviour
Analytics — would be enabled in Sentinel
to provide baseline behavioural
profiles for each user and alert on
deviations that individual analytics
rules miss. UEBA detects the subtle
anomalies that pattern-matching rules
cannot — a user who normally generates
50 events per day suddenly generating
5000, or an account that never
authenticates outside business hours
suddenly authenticating at 3am.

The threat hunting programme would
be formalised with a hunting hypothesis
backlog, scheduled hunting sessions,
and a process for converting successful
hunts into analytics rules — closing
the loop between proactive and reactive
detection.

---

Uzma Shabbir
Cloud Security Engineer | AZ-104 | AZ-500
[GitHub](https://github.com/UzmaSami) •
[LinkedIn](https://linkedin.com/in/uzma-shabbir-034361128)
