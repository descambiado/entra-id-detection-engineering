# Administrator Registered MFA Method on Behalf of User

## Technique
**MITRE ATT&CK**: [T1556.006 — Modify Authentication Process: Multi-Factor Authentication](https://attack.mitre.org/techniques/T1556/006/)  
**Tactic**: Persistence, Defense Evasion

## What the attacker is doing

An attacker who has obtained administrator credentials registers a new MFA method on a target user account. This can be an authenticator app, phone number, FIDO2 key, or any supported method. The goal is account takeover that survives a password reset.

The attack sequence:
1. Attacker compromises an admin account (via phishing, credential stuffing, or session hijacking)
2. Attacker navigates to Entra ID > Users > [target user] > Authentication methods
3. Attacker registers their own device/number as an MFA method on the target account
4. If the target resets their password (triggered by a security alert), the attacker still authenticates using their registered MFA method
5. The attacker now has persistent access independent of the password

This is distinct from the `azure_tap_added` rule (which detects specifically Temporary Access Pass additions) and `azure_change_to_authentication_method` (which detects self-service user registration). Admin-initiated changes on behalf of another user are a specific, higher-severity signal because:
- The actor is not the account owner
- Legitimate admin MFA management is rare and should always be tracked against help desk tickets
- It directly enables account takeover even after password remediation

## Why standard detections miss it

The operation `Admin registered security info` generates a different audit event from user self-service registration (`User registered security info`). Most detection content focuses on the self-service path. Admin-initiated registration has no dedicated detection in the SigmaHQ repository beyond the TAP-specific rule.

## Detection

### KQL (Microsoft Sentinel)

```kql
let starttime = todatetime('{{StartTimeISO}}');
let endtime   = todatetime('{{EndTimeISO}}');
AuditLogs
| where TimeGenerated between (starttime .. endtime)
| where OperationName in~ (
      "Admin registered security info",
      "Admin updated security info",
      "Admin deleted security info"
  )
| where Result =~ "success"
| extend TargetUpn    = tolower(tostring(TargetResources[0].userPrincipalName))
| extend MethodType   = tostring(TargetResources[0].displayName)
| extend ActorUpn     = tolower(tostring(parse_json(tostring(InitiatedBy.user)).userPrincipalName))
| extend ActorIp      = tostring(parse_json(tostring(InitiatedBy.user)).ipAddress)
| where TargetUpn != ActorUpn  // exclude self-service via admin portal
| extend AccountName      = tostring(split(TargetUpn, "@")[0])
| extend AccountUPNSuffix = tostring(split(TargetUpn, "@")[1])
| project TimeGenerated, OperationName, TargetUpn, AccountName, AccountUPNSuffix, MethodType, ActorUpn, ActorIp, CorrelationId
| sort by TimeGenerated desc
```

### SIGMA

```yaml
title: Administrator Registered or Modified MFA Method on Behalf of User
id: bf01ebb6-7dde-40f4-b502-cd22cb121859
related:
    - id: 4d78a000-ab52-4564-88a5-7ab5242b20c7
      type: similar
    - id: fa84aaf5-8142-43cd-9ec2-78cfebf878ce
      type: similar
status: test
tags:
    - attack.persistence
    - attack.defense-evasion
    - attack.t1556.006
detection:
    selection:
        OperationName:
            - 'Admin registered security info'
            - 'Admin updated security info'
            - 'Admin deleted security info'
    condition: selection
level: high
```

**Contributed**: [SigmaHQ/sigma#6012](https://github.com/SigmaHQ/sigma/pull/6012)

## False Positives

- Help desk teams performing MFA resets for locked-out users following approved procedures
- Automated identity governance workflows managing auth methods programmatically

**Analyst note**: Correlate every result against your help desk ticketing system. If there is no open ticket for the target user, treat as an IOC. Also check whether the actor performed this action outside business hours or from an unusual IP.

## Investigation Steps

1. Identify the target user and confirm whether they have an open help desk ticket for MFA issues
2. Contact the target user out-of-band to verify whether they authorized the change
3. Check the actor's recent activity: sign-in country, IP, device, MFA method used
4. If unauthorized: immediately remove the attacker's registered method, force password reset, revoke all sessions for both the target and actor accounts
5. Determine if the same actor performed this action on other accounts

## References

- [Microsoft: Manage user authentication methods](https://learn.microsoft.com/en-us/entra/identity/authentication/howto-mfa-userdevicesettings)
- [MITRE T1556.006](https://attack.mitre.org/techniques/T1556/006/)
