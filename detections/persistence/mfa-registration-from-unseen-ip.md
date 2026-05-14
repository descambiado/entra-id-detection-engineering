# MFA Registration from Unseen IP

## Technique
**MITRE ATT&CK**: [T1556.006 — Modify Authentication Process: Multi-Factor Authentication](https://attack.mitre.org/techniques/T1556/006/)  
**Tactic**: Persistence, Defense Evasion

## What the attacker is doing

An attacker who has obtained a user's password registers a new MFA method from an IP address that has never been used by that user to sign in. Once registered, the attacker's device becomes a valid second factor — they can authenticate as the victim even after a password reset, because the MFA method is tied to the attacker's device, not the victim's.

This technique is widely used in AiTM (Adversary-in-the-Middle) phishing campaigns. The attacker intercepts the victim's session token, uses it to register their own MFA method, and then has persistent access via their own credentials rather than relying on the stolen token (which may expire or be revoked).

The IP novelty signal is strong because:
- Legitimate users register MFA from their own devices on their home or corporate network
- An IP that has never appeared in 30 days of successful sign-ins is genuinely anomalous
- This approach avoids false positives from flagging all MFA registrations (which includes legitimate new device setups)

This detection does not require Entra ID P2 licensing. It uses IP novelty rather than identity protection risk scores.

## Detection

### KQL (Microsoft Sentinel)

```kql
let starttime = todatetime('{{StartTimeISO}}');
let endtime   = todatetime('{{EndTimeISO}}');
let ipLookback = starttime - 30d;
let BaselineIPs =
    SigninLogs
    | where TimeGenerated between (ipLookback .. starttime)
    | where ResultType == 0
    | where isnotempty(IPAddress)
    | extend UserUpn = tolower(UserPrincipalName)
    | summarize KnownIPs = make_set(IPAddress) by UserUpn;
AuditLogs
| where TimeGenerated between (starttime .. endtime)
| where OperationName =~ "User registered security info"
| where Result =~ "success"
| extend UserUpn    = tolower(tostring(TargetResources[0].userPrincipalName))
| extend UserId     = tostring(TargetResources[0].id)
| extend MethodType = tostring(TargetResources[0].displayName)
| extend RegIp      = tostring(parse_json(tostring(InitiatedBy.user)).ipAddress)
| where isnotempty(RegIp) and isnotempty(UserUpn)
| join kind=leftouter BaselineIPs on $left.UserUpn == $right.UserUpn
| where isnull(KnownIPs) or not(set_has_element(KnownIPs, RegIp))
| extend AccountName      = tostring(split(UserUpn, "@")[0])
| extend AccountUPNSuffix = tostring(split(UserUpn, "@")[1])
| project TimeGenerated, UserUpn, AccountName, AccountUPNSuffix, UserId,
    MethodType, RegIp, KnownIPCount = array_length(KnownIPs), CorrelationId
| sort by TimeGenerated desc
```

**Contributed**: [Azure-Sentinel#14262](https://github.com/Azure/Azure-Sentinel/pull/14262)

## False Positives

- Users registering MFA from a new home network, hotel Wi-Fi, or travel location
- Users setting up MFA for the first time (no baseline → `KnownIPCount` = 0)
- VPN exit nodes not previously used for sign-in

**Analyst note**: The `KnownIPCount` column is your primary triage field. A value of 0 means the user has no sign-in history in the baseline window — this is a new account or one that has never used Entra ID interactively, and requires different handling. A user with 500 known IPs registering from an unknown IP warrants closer investigation than a user with 3 known IPs.

## Investigation Steps

1. Contact the user out-of-band to verify whether they authorized the MFA registration
2. Check whether there was a preceding sign-in from the same IP using the user's credentials
3. Review whether any forwarding rules, consent grants, or permission changes occurred after the MFA registration
4. Check for concurrent anomalous activity on the same account
5. If unauthorized: immediately remove the registered method, force password reset, revoke all sessions

## References

- [Microsoft: How MFA works](https://learn.microsoft.com/en-us/entra/identity/authentication/concept-mfa-howitworks)
- [MITRE T1556.006](https://attack.mitre.org/techniques/T1556/006/)
