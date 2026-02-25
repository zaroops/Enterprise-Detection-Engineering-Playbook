
---

## **3️⃣ detection-use-cases/brute-force-detection.md**

# Brute Force Detection

## Threat Description
Brute force attacks attempt multiple password guesses to gain unauthorized access. Early detection is crucial to prevent lateral movement or privilege escalation.

## Logs Involved
- Windows Security Event Logs (4625 – failed logon)
- Sysmon Event 4625 correlation
- Domain Controller logs

## SPL Query Example
```spl
index=wineventlog EventCode=4625
| stats count by TargetUserName, IpAddress
| where count > 5
```

## Investigation Steps
- Identify user accounts with multiple failed logons.
- Correlate IP addresses to see if attacks are internal or external.
- Check if the IPs have other suspicious activity (malware, other failed logons).

## Tuning Considerations
- Adjust threshold based on normal login patterns.
- Exclude service accounts or monitoring accounts.
- Consider failed logons followed by a successful logon for early compromise detection.

## MITRE ATT&CK Mapping
- T1110 – Brute Force
