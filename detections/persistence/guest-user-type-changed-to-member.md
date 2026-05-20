# Guest User Type Changed to Member

## Technique
**MITRE ATT&CK**: [T1098 — Account Manipulation](https://attack.mitre.org/techniques/T1098/)  
**Tactic**: Persistence

## What the attacker is doing

In Entra ID, external collaborators join a tenant as Guest accounts. Guest accounts operate under a restricted permission model: they cannot enumerate tenant users and groups, have no access to internal SharePoint sites that exclude guests, and are visible as external in most directory listings. Member accounts have full directory read access by default and are treated as internal by most authorization checks.

An attacker who compromises a guest account — through a phishing token, a leaked credential, or an AiTM session — may escalate it to Member type using a User Administrator or Global Administrator account they control. This is a one-field change (`UserType: Guest → Member`) that:

- Grants the account full directory read access, enabling enumeration of users, groups, roles, and applications
- Removes the "external" visibility markers that might trigger analyst scrutiny
- Bypasses Conditional Access policies scoped to external or guest identities
- Persists across password resets of the original guest account

This technique is quiet because `Update user` fires continuously in any active tenant. The signal is the specific `UserType` property change — which most detections don't filter on.

## Why standard detections miss it

Generic `Update user` detections produce so much noise that most teams suppress or tier them to low severity. Detections focused on role assignments miss this entirely because no role is assigned. The account just becomes a different type.

## Detection

### KQL (Microsoft Sentinel)

```kql
let timeframe = 1d;
AuditLogs
| where TimeGenerated >= ago(timeframe)
| where OperationName =~ "Update user"
| where Result =~ "success"
| mv-expand ModProp = TargetResources[0].modifiedProperties
| where tostring(ModProp.displayName) =~ "UserType"
| extend OldUserType = tostring(ModProp.oldValue)
| extend NewUserType = tostring(ModProp.newValue)
| where OldUserType has "Guest" and NewUserType has "Member"
| extend TargetUpn  = tostring(TargetResources[0].userPrincipalName)
| extend TargetId   = tostring(TargetResources[0].id)
| extend ActorUpn   = tostring(InitiatedBy.user.userPrincipalName)
| extend ActorApp   = tostring(InitiatedBy.app.displayName)
| extend Actor      = iff(isnotempty(ActorUpn), ActorUpn, ActorApp)
| extend ActorIp    = iff(
      isnotempty(tostring(InitiatedBy.user.ipAddress)),
      tostring(InitiatedBy.user.ipAddress),
      tostring(InitiatedBy.app.ipAddress))
| extend AccountName      = iff(TargetUpn has "@",
      tostring(split(TargetUpn, "@")[0]), TargetUpn)
| extend AccountUPNSuffix = iff(TargetUpn has "@",
      tostring(split(TargetUpn, "@")[1]), "")
| project
    TimeGenerated,
    TargetUpn,
    AccountName,
    AccountUPNSuffix,
    TargetId,
    OldUserType,
    NewUserType,
    Actor,
    ActorIp,
    CorrelationId
| sort by TimeGenerated desc
```

**Contributed**: [Azure/Azure-Sentinel#14307](https://github.com/Azure/Azure-Sentinel/pull/14307)

## False Positives

- B2B collaboration migrations where a partner organization's users are intentionally promoted to full members
- Organizational restructuring where former external contractors are onboarded as permanent employees and converted in place

**Analyst note**: Check when the guest account was originally created and whether the converting actor's role was recently assigned. A guest account created within the last 7 days and immediately promoted to member is a strong IOC. Also check post-conversion sign-in activity in `SigninLogs` — a Member-type account signing in to access directory enumeration APIs shortly after conversion is consistent with initial reconnaissance.

## Investigation Steps

1. Check when the target account was originally invited as a guest: `AuditLogs | where OperationName =~ "Invite external user" | where TargetResources[0].id == "<user-id>"`
2. Check what the actor's role is and when it was assigned
3. Review post-conversion sign-ins: `SigninLogs | where UserId == "<user-id>" | where TimeGenerated >= <ConversionTime>`
4. Check for directory enumeration: Graph API calls to `/users`, `/groups`, `/applications` from the converted account
5. Determine whether the conversion was authorized via a help desk ticket or onboarding workflow

## References

- [Microsoft: Guest user access in Entra ID](https://learn.microsoft.com/en-us/entra/external-id/user-properties)
- [MITRE T1098](https://attack.mitre.org/techniques/T1098/)
