
---
# Hunting for Lateral Movement in Active Directory Environments

## Hypothesis
Compromised accounts may move laterally across AD hosts via network logons, remote services, or PsExec.

## Logs to Review
- Windows Security Event Logs (4624, 4648, 4672)
- Sysmon Network Connections (Event 3)
- PowerShell logs for remote commands

## Query Design
- Identify logons from unusual hosts
- Correlate logons with remote service creation
- Look for unusual PowerShell commands or WMI usage

## Investigation Workflow
1. Review Event 4624 logons across hosts for anomalies.
2. Identify hosts accessed from unusual source IPs or accounts.
3. Investigate linked PowerShell or remote commands.
4. Document anomalies for further threat investigation.

## Findings / Interpretation
- Hosts accessed from a single account outside normal schedule → possible compromise
- Remote services created with admin privileges → potential lateral movement
