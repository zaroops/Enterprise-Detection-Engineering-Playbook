# Event ID 4624 – Successful Logon Analysis

## Description
Event 4624 logs successful user logons to a Windows system. Critical for detecting lateral movement, compromised accounts, and abnormal authentication patterns.

## Field Breakdown
- **TargetUserName** – Account name that logged on
- **TargetDomainName** – Domain of the account
- **LogonType** – Type of logon (e.g., 2 = interactive, 3 = network)
- **IpAddress** – Source IP of logon
- **WorkstationName** – Host machine name
- **SubjectUserName** – User performing the action (system account or process)

## Detection Opportunities
- Multiple logons from unusual IPs in a short time → potential brute force
- Logons at odd hours → potential compromised account
- Logons using unusual LogonType → remote or lateral movement

## Example SPL Query
```spl
index=wineventlog EventCode=4624 
| stats count by TargetUserName, IpAddress, LogonType 
| where count > 5
```
## False Positive Considerations
- Service accounts logging in multiple times may trigger alerts
- Remote logons from VPN or legitimate admin activity

## MITRE ATT&CK Mapping
- T1078 – Valid Accounts
- T1087.002 – Account Discovery: Domain Accounts
- T1566 – Credential Access
