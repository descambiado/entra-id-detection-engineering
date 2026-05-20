# Successful Sign-in from Unseen IP After MFA Disabled

## Technique
**MITRE ATT&CK**: [T1556.006 — Modify Authentication Process: Multi-Factor Authentication](https://attack.mitre.org/techniques/T1556/006/), [T1078.004 — Valid Accounts: Cloud Accounts](https://attack.mitre.org/techniques/T1078/004/)  
**Tactic**: Persistence, Credential Access

## What the attacker is doing

After gaining control of an account, an attacker who has captured only the password (not an active session or MFA method) needs to eliminate the MFA requirement before they can log in from their own infrastructure. The sequence:

1. Attacker authenticates to a session with MFA (via AiTM proxy, session token theft, or privileged admin access)
2. Attacker disables MFA for the target account or deletes the MFA method registration
3. Attacker signs in using the password alone from their own IP
4. Sign-in succeeds without MFA challenge

The second event — the sign-in from an IP that has never been seen for this account — is individually low-signal (new IP sign-ins are common). The first event — MFA disable — is individually noisy (IT helpdesk disables MFA for locked-out users routinely). The 60-minute correlation window between them is the signal.

This pattern appears in AiTM post-compromise activity and in helpdesk social engineering attacks where the attacker convinces support to disable MFA for the compromised account.

## Why standard detections miss it

Detections watching `Disable Strong Authentication` fire on every helpdesk-initiated MFA reset, which in most tenants is high-volume and handled as low severity. Sign-ins from new IPs are suppressed or deprioritized in environments with a mobile workforce. Neither event alone filters to actionable signal.

The detection gap is the absence of cross-source temporal correlation: the AuditLog operation and the subsequent SigninLog event are in different tables, and the implicit "this account's MFA was just disabled" context is not carried forward into the sign-in evaluation.

## Detection

### KQL (Microsoft Sentinel)

```kql
let timeframe = 1d;
let correlationWindow = 60m;
let lookback = 30d;
let DisabledMFA =
    AuditLogs
    | where TimeGenerated >= ago(timeframe)
    | where OperationName in~ (
          "Disable Strong Authentication",
          "User deleted security info"
      )
    | where Result =~ "success"
    | extend AffectedUser = tolower(tostring(TargetResources[0].userPrincipalName))
    | where isnotempty(AffectedUser)
    | project AffectedUser, MFADisabledTime = TimeGenerated;
let KnownIPs =
    SigninLogs
    | where TimeGenerated >= ago(timeframe + lookback) and TimeGenerated < ago(timeframe)
    | where ResultType == 0
    | summarize KnownIPSet = make_set(IPAddress)
        by UserPrincipalName = tolower(UserPrincipalName);
SigninLogs
| where TimeGenerated >= ago(timeframe)
| where ResultType == 0
| extend UserUpn = tolower(UserPrincipalName)
| join kind=inner DisabledMFA on $left.UserUpn == $right.AffectedUser
| where TimeGenerated >= MFADisabledTime and TimeGenerated <= MFADisabledTime + correlationWindow
| join kind=leftouter KnownIPs on $left.UserUpn == $right.UserPrincipalName
| where not(set_has_element(KnownIPSet, IPAddress))
| extend AccountName      = tostring(split(UserUpn, "@")[0])
| extend AccountUPNSuffix = tostring(split(UserUpn, "@")[1])
| project
    TimeGenerated,
    UserUpn,
    AccountName,
    AccountUPNSuffix,
    MFADisabledTime,
    IPAddress,
    AppDisplayName,
    Location,
    AutonomousSystemNumber,
    CorrelationId
| sort by TimeGenerated desc
```

**Contributed**: [Azure/Azure-Sentinel#14311](https://github.com/Azure/Azure-Sentinel/pull/14311)

## False Positives

- IT helpdesk disabling MFA for a locked-out user who then signs in from a new device or location (home, travel)
- Self-service MFA reset followed by sign-in from a new machine or network
- Employee returning from extended leave who clears old MFA methods and logs in from a new home IP

**Analyst note**: Check who disabled MFA — if the disabling actor and the signing-in user are different accounts, the confidence is higher. Review `AutonomousSystemNumber`: residential ISPs (consumer broadband) are more consistent with legitimate new-location sign-ins; hosting providers, VPN services, or Tor exit nodes are strong indicators of attacker-controlled infrastructure.

## Investigation Steps

1. Determine who disabled MFA: `AuditLogs | where OperationName in~ ("Disable Strong Authentication", "User deleted security info") | where TargetResources[0].userPrincipalName =~ "<affected-user>"`
2. Check if the disabling was helpdesk-initiated (actor is a service account or admin UPN) or self-service (actor equals affected user)
3. Verify the sign-in IP's reputation: ASN, threat intelligence, geolocation — hosting/VPN/Tor requires immediate escalation
4. Check whether the account has MFA re-registered after the sign-in: `AuditLogs | where OperationName =~ "User registered security info" | where TargetResources[0].userPrincipalName =~ "<affected-user>" | where TimeGenerated > <signin-time>`
5. Review subsequent activity for the account: email rules, forwarding changes, access to sensitive data, role changes

## References

- [Microsoft: Authentication methods activity](https://learn.microsoft.com/en-us/entra/identity/authentication/howto-authentication-methods-activity)
- [Microsoft Security: AiTM phishing campaigns](https://www.microsoft.com/en-us/security/blog/2022/07/12/from-cookie-theft-to-bec-attackers-use-aitm-phishing-sites-as-entry-point-to-further-financial-fraud/)
- [MITRE T1556.006](https://attack.mitre.org/techniques/T1556/006/)
- [MITRE T1078.004](https://attack.mitre.org/techniques/T1078/004/)
