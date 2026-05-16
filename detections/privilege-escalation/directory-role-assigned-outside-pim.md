# Privileged Directory Role Assigned Outside PIM Workflow

## Technique
**MITRE ATT&CK**: [T1098.003 — Additional Cloud Roles](https://attack.mitre.org/techniques/T1098/003/)  
**Tactic**: Persistence, Privilege Escalation

## What the attacker is doing

After gaining sufficient access (Application Administrator, Privileged Role Administrator, or Global Administrator), an attacker assigns a privileged directory role directly to an account they control — bypassing the Privileged Identity Management workflow. This matters because:

- PIM requires justification, approval (if configured), and logs the activation with a business reason
- Direct assignment leaves no justification trail and creates a permanent role, not a time-limited one
- An attacker who bypasses PIM gets a role that persists until manually revoked, survives the victim account's password reset, and does not require MFA challenge on next use

The distinguishing KQL signal: PIM activations log as `"Add member to role. (PIM activation)"`. Direct non-PIM assignments log as `"Add member to role."` — exact string, no suffix.

## Why standard detections miss it

Most AuditLog-based role assignment rules use `has` or `contains` on the OperationName, which matches both the PIM activation and direct assignment variants. They generate noise on every PIM activation event, causing analysts to suppress or tune the alert entirely. This detection fires only on the direct assignment path by using exact case-insensitive equality (`=~`).

## Detection

### KQL (Microsoft Sentinel)

```kql
let timeframe = 14d;
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
AuditLogs
| where TimeGenerated >= ago(timeframe)
| where Category =~ "RoleManagement"
| where OperationName =~ "Add member to role."
| where Result =~ "success"
| extend ActorUpn = tostring(InitiatedBy.user.userPrincipalName)
| extend ActorApp = tostring(InitiatedBy.app.displayName)
| extend Actor    = iff(isnotempty(ActorUpn), ActorUpn, ActorApp)
| extend ActorIp  = iff(
      isnotempty(tostring(InitiatedBy.user.ipAddress)),
      tostring(InitiatedBy.user.ipAddress),
      tostring(InitiatedBy.app.ipAddress))
| extend TargetUpn = tostring(TargetResources[0].userPrincipalName)
| extend TargetId  = tostring(TargetResources[0].id)
| mv-expand ModProp = TargetResources[0].modifiedProperties
| where tostring(ModProp.displayName) =~ "Role.DisplayName"
| extend RoleName = trim('"', tostring(ModProp.newValue))
| where RoleName in~ (PrivilegedRoles)
| extend AccountName      = iff(TargetUpn has "@", tostring(split(TargetUpn, "@")[0]), TargetUpn)
| extend AccountUPNSuffix = iff(TargetUpn has "@", tostring(split(TargetUpn, "@")[1]), "")
| project TimeGenerated, Actor, ActorIp, TargetUpn, AccountName, AccountUPNSuffix,
          TargetId, RoleName, CorrelationId
| sort by TimeGenerated desc
```

**Contributed**: [Azure/Azure-Sentinel#14281](https://github.com/Azure/Azure-Sentinel/pull/14281)

## False Positives

- Break-glass account management: permanent GA assignment for emergency access accounts is a documented best practice
- Initial tenant provisioning where PIM has not yet been configured for all privileged roles
- Automated provisioning pipelines with Application Administrator rights that assign roles as part of onboarding workflows

**Analyst note**: Check if PIM is enabled for the assigned role. If PIM is configured for eligible assignment and someone made a permanent assignment instead, it is either misconfiguration or deliberate bypass — investigate the actor. If PIM is not configured for that role, this is a governance gap rather than an IOC, but still worth reviewing.

## Investigation Steps

1. Identify the actor: check `InitiatedBy.user.userPrincipalName` or `InitiatedBy.app.displayName`
2. Verify the actor's own role assignments — did they recently receive Application Administrator or Privileged Role Administrator?
3. Check if PIM is configured as eligible-only for the assigned role in Entra ID > Roles and Administrators > Role settings
4. Review the target account's sign-in history after the assignment: `SigninLogs | where UserPrincipalName == "<target>" | where TimeGenerated > <assignment time>`
5. Check if the target account is newly created or recently modified

## References

- [Microsoft PIM deployment guidance](https://learn.microsoft.com/en-us/entra/id-governance/privileged-identity-management/pim-deployment-plan)
- [MITRE T1098.003](https://attack.mitre.org/techniques/T1098/003/)
