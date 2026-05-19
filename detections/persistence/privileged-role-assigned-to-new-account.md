# Privileged Role Assigned to Newly Created Account

## Technique
**MITRE ATT&CK**: [T1098.003 — Additional Cloud Roles](https://attack.mitre.org/techniques/T1098/003/), [T1136.003 — Create Account: Cloud Account](https://attack.mitre.org/techniques/T1136/003/)  
**Tactic**: Persistence, Privilege Escalation

## What the attacker is doing

An attacker with Global Administrator or User Administrator access can create a new account in Entra ID and immediately assign it a privileged role. The new account becomes a persistent backdoor: it survives password resets of the originally compromised account, it can have MFA registered to attacker-controlled devices, and it may not appear in existing access reviews if reviewers assume all admin accounts are known-good.

The creation-to-role-assignment window is almost always under an hour in attacker operations. The attacker wants to confirm the account is functional before moving on. The tight time window between `Add user` and `Add member to role` events for the same user is the detection signal.

## Why standard detections miss it

- Account creation and role assignment are both normal, frequent operations in any actively managed tenant
- The events are logged separately in `AuditLogs` and require a join to correlate
- Security teams often review role assignments in isolation without considering how recently the account was created

## Detection

### KQL (Microsoft Sentinel)

```kql
let timeframe = 7d;
let creationWindow = 24h;
let PrivilegedRoles = dynamic([
    "Global Administrator",
    "Privileged Role Administrator",
    "Application Administrator",
    "Cloud Application Administrator",
    "Exchange Administrator",
    "SharePoint Administrator",
    "User Account Administrator",
    "Authentication Administrator",
    "Privileged Authentication Administrator",
    "Security Administrator",
    "Hybrid Identity Administrator"
]);
let NewAccounts =
    AuditLogs
    | where TimeGenerated >= ago(timeframe)
    | where OperationName =~ "Add user"
    | where Result =~ "success"
    | project
        AccountCreatedTime = TimeGenerated,
        UserId             = tostring(TargetResources[0].id),
        NewUserUpn         = tostring(TargetResources[0].userPrincipalName);
AuditLogs
| where TimeGenerated >= ago(timeframe)
| where Category =~ "RoleManagement"
| where OperationName =~ "Add member to role."
| where Result =~ "success"
| extend TargetUserId = tostring(TargetResources[0].id)
| extend TargetUpn    = tostring(TargetResources[0].userPrincipalName)
| mv-expand ModProp = TargetResources[0].modifiedProperties
| where tostring(ModProp.displayName) =~ "Role.DisplayName"
| extend RoleName = trim('"', tostring(ModProp.newValue))
| where RoleName in~ (PrivilegedRoles)
| join kind=inner NewAccounts on $left.TargetUserId == $right.UserId
| where TimeGenerated between (AccountCreatedTime .. (AccountCreatedTime + creationWindow))
| extend ActorUpn = tostring(InitiatedBy.user.userPrincipalName)
| extend ActorApp = tostring(InitiatedBy.app.displayName)
| extend Actor    = iff(isnotempty(ActorUpn), ActorUpn, ActorApp)
| extend ActorIp  = iff(
      isnotempty(tostring(InitiatedBy.user.ipAddress)),
      tostring(InitiatedBy.user.ipAddress),
      tostring(InitiatedBy.app.ipAddress))
| extend AccountName      = iff(TargetUpn has "@", tostring(split(TargetUpn, "@")[0]), TargetUpn)
| extend AccountUPNSuffix = iff(TargetUpn has "@", tostring(split(TargetUpn, "@")[1]), "")
| project
    TimeGenerated,
    RoleName,
    TargetUpn,
    AccountName,
    AccountUPNSuffix,
    AccountCreatedTime,
    Actor,
    ActorIp,
    CorrelationId
| sort by TimeGenerated desc
```

**Contributed**: [Azure/Azure-Sentinel#14299](https://github.com/Azure/Azure-Sentinel/pull/14299)

## False Positives

- Legitimate onboarding of a new admin where account creation and role assignment happen in the same IT workflow (same day is expected)
- Automated provisioning pipelines that create service accounts and assign roles in a single deployment

**Analyst note**: The key differentiator is the actor. If the same actor who created the account also assigned the role, this is likely a single provisioning operation. If a different actor assigned the role — or if the role assignment was made from a different IP or at a different time than account creation — treat as suspicious. Also check whether the new account has MFA registered and whether that registration was made from a known device.

## Investigation Steps

1. Identify who created the account and who assigned the role — check whether they are the same actor
2. Check whether MFA methods were registered on the new account: `AuditLogs | where OperationName =~ "User registered security info" | where TargetResources[0].id == "<userid>"`
3. Check sign-in activity for the new account in `SigninLogs` to see if it has been used
4. Review the actor's full `AuditLogs` activity in the session that included the role assignment
5. If the account is still active, consider disabling it and rotating credentials for the actor

## References

- [MITRE T1098.003](https://attack.mitre.org/techniques/T1098/003/)
- [MITRE T1136.003](https://attack.mitre.org/techniques/T1136/003/)
