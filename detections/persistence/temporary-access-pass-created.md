# Temporary Access Pass Created for User Account

## Technique
**MITRE ATT&CK**: [T1556.006 — Modify Authentication Process: Multi-Factor Authentication](https://attack.mitre.org/techniques/T1556/006/), [T1098 — Account Manipulation](https://attack.mitre.org/techniques/T1098/)  
**Tactic**: Persistence, Credential Access

## What the attacker is doing

A Temporary Access Pass (TAP) is a time-limited, PIN-based credential issued by an Entra ID administrator that allows a user to authenticate without their existing password or MFA methods. It is designed for onboarding new employees or helping locked-out users recover access.

An attacker with User Administrator or Authentication Administrator access can issue a TAP for any non-admin account in the tenant. With the TAP, they can:
- Sign in to the target account without knowing the current password
- Register new FIDO2 keys, authenticator apps, or phone numbers as MFA methods — effectively taking full, persistent control of the account
- Use the account during the TAP validity window (typically 1–8 hours, configurable up to 30 days) without triggering credential-based alerts

TAP abuse is distinct from direct password reset because it leaves the original password unchanged. The target user may not notice anything wrong until their next sign-in attempt. By that point, the attacker has already registered persistent MFA methods and the TAP has expired.

## Why standard detections miss it

- TAP creation is a low-frequency, expected operation in environments that use it for onboarding
- The `AuditLogs` event for TAP creation is not a dedicated operation — it appears as `Update user` or `Admin registered security info` with a property value containing "TemporaryAccessPass"
- Most alert rules focus on password resets, not TAP creation

## Detection

### KQL (Microsoft Sentinel)

```kql
let timeframe = 1d;
AuditLogs
| where TimeGenerated >= ago(timeframe)
| where Category =~ "UserManagement"
| where OperationName in~ (
      "Admin registered security info",
      "Create Temporary Access Pass method for user",
      "Update user"
  )
| where Result =~ "success"
| where tostring(TargetResources) has "TemporaryAccessPass"
| extend TargetUpn  = tostring(TargetResources[0].userPrincipalName)
| extend TargetId   = tostring(TargetResources[0].id)
| extend ActorUpn   = tostring(InitiatedBy.user.userPrincipalName)
| extend ActorApp   = tostring(InitiatedBy.app.displayName)
| extend Actor      = iff(isnotempty(ActorUpn), ActorUpn, ActorApp)
| extend ActorIp    = iff(
      isnotempty(tostring(InitiatedBy.user.ipAddress)),
      tostring(InitiatedBy.user.ipAddress),
      tostring(InitiatedBy.app.ipAddress))
| extend AccountName      = iff(TargetUpn has "@", tostring(split(TargetUpn, "@")[0]), TargetUpn)
| extend AccountUPNSuffix = iff(TargetUpn has "@", tostring(split(TargetUpn, "@")[1]), "")
| project
    TimeGenerated,
    TargetUpn,
    AccountName,
    AccountUPNSuffix,
    TargetId,
    Actor,
    ActorIp,
    OperationName,
    CorrelationId
| sort by TimeGenerated desc
```

**Contributed**: [Azure/Azure-Sentinel#14299](https://github.com/Azure/Azure-Sentinel/pull/14299)

## False Positives

- IT helpdesk issuing TAPs to users who are locked out or onboarding new devices
- Automated onboarding workflows that provision TAPs for new hires
- Bulk resets during an Active Directory migration or device refresh cycle

**Analyst note**: TAP creation volume should be very low in a steady-state environment — a few per week at most. Any spike is worth investigating. Cross-reference the `TargetUpn` against the HR system to confirm whether the user is actually in an onboarding or device replacement workflow. If the target account is a privileged account (Global Admin, Exchange Admin, etc.), treat as critical regardless of volume — admins should never need TAPs in normal operations.

## Investigation Steps

1. Confirm whether the TAP was issued through a formal IT process (check with helpdesk)
2. Check whether the target account had new MFA methods registered after the TAP was created: `AuditLogs | where OperationName =~ "User registered security info" | where TargetResources[0].id == "<userid>"`
3. Review `SigninLogs` for the target account in the TAP validity window for sign-ins from unknown IPs
4. Check `AuditLogs` for the actor who created the TAP — look for other TAP creations or admin operations in the same session
5. If suspicious: revoke the TAP immediately, disable any newly registered MFA methods, force password reset on the target account

## References

- [Microsoft: Temporary Access Pass](https://learn.microsoft.com/en-us/entra/identity/authentication/howto-authentication-temporary-access-pass)
- [MITRE T1556.006](https://attack.mitre.org/techniques/T1556/006/)
- [MITRE T1098](https://attack.mitre.org/techniques/T1098/)
