# Event ID 4625 – Failed Logon Analysis

## Description
Event 4625 tells us when a user unsuccessfully logs on. It records every failed logon attempt to a local device, regardless of account type or location. It captures the identity and source of the attempted login, and is the primary way to detect brute-force attacks and credential harvesting. 

## Field Breakdown
- **TargetUserName** – Account name that logged on
- **TargetDomainName** – Domain of the account
- **LogonType** – Type of logon (ex., 2 = interactive, 3 = network)
- **Status** - Specific hexcode and reason for the failure (ex. 0xC000006D)
- **IpAddress** – Source IP of logon
- **WorkstationName** – Host machine name
- **SubjectAccountName** – User performing the action (system account or process)
- **LogonProcess** - Specific executable on local system that called for the logon.

## Commonly involved failure Status and Substatus Codes
- 0xC0000064: User name does not exist (Indicates Account Enumeration).
- 0xC000006A: Correct username, but wrong password (Indicates Password Guessing or a Brute Force).
- 0xC0000234: The user is currently locked out.
- 0xC0000072: Account is disabled.

## Detection Opportunities
- Multiple logons from unusual IPs in a short time → potential brute force
- Logons at odd hours → potential compromised account
- Password Spraying → failed attempts across MANY accounts
- Logons using unusual LogonType → remote or lateral movement
- Logons from physically impossible location (requires Geolocation enrichment of some sort), with geographic location inconsistnet.

## Example SPL Query
```spl
index=wineventlog EventCode=4625 
| bucket _time span=5m 
| stats count dc(TargetUserName) as unique_users by _time, IpAddress, TargetUserName
| where count > 10
```
- Slightly more advanced, but this splunk query looks for more than 10 failures from a single user in a 5 minute window to potentially detect brute forcing.
```spl
index=wineventlog EventCode=4625 
| stats dc(TargetUserName) as distinct_targets values(TargetUserName) as users by IpAddress 
| where distinct_targets > 5
```
- One IP targetting many accounts.
- 
## False Positive Considerations
- Expired passwords or users who havent updated standard passwords will generate 4625s.
- Service accounts logging in multiple times may trigger alerts
- Network scanners inentionally performing credential checks may trigger this.

## MITRE ATT&CK Mapping
- T1110 - Brute Force
  - T1110.001 - Password Guessing (targeting specific account with many passwords)
  - T1110.003 - Password Spraying (targeting many accounts with one password)
- T1078 – Valid Accounts
- T1087 - Account Discovery
