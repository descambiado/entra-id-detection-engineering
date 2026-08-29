# Role-Assignable Group Created

## Technique
**MITRE ATT&CK**: [T1098.003 - Account Manipulation: Additional Cloud Roles](https://attack.mitre.org/techniques/T1098/003/)
**Tactic**: Privilege Escalation, Persistence

## What the attacker is doing

Group role-assignability (`isAssignableToRole` set to `true`) can only be set when a group is created; Entra ID does not allow converting an existing group into a role-assignable one afterward, and creating one requires the actor to hold at least the Privileged Role Administrator role. A maximum of 500 role-assignable groups are permitted per tenant, so every match here is inherently rare and should map to a known change.

An attacker who has obtained Privileged Role Administrator or Global Administrator access can create a role-assignable group with an innocuous display name, then add members or owners to it (see the companion detection below) and later assign a directory role to the group. Because role-assignable groups exist specifically so that group membership grants a role, standard "Add member to role" monitoring never fires for the accounts that gain access this way; the group creation and its membership changes are the only audit signal.

## Why standard detections miss it

Detections built around `Add member to role` miss this entirely, since the accounts that ultimately hold the role never appear as the target of that operation, only the group does, and often much later. By design there is no legitimate high-volume use of role-assignable group creation in a well-run tenant, which makes this a high-signal, low-noise detection when watched directly instead of relying on downstream role-assignment monitoring.

## Detection

### KQL (Microsoft Sentinel)

```kql
let timeframe = 14d;
AuditLogs
| where TimeGenerated >= ago(timeframe)
| where Category =~ "GroupManagement"
| where OperationName =~ "Add group"
| where Result =~ "success"
| mv-expand ModProp = TargetResources[0].modifiedProperties
| extend PropName = tostring(ModProp.displayName)
| extend NewValue = tostring(ModProp.newValue)
| where PropName has "IsAssignableToRole" or NewValue has "isAssignableToRole"
| where NewValue has "true"
| extend GroupName = tostring(TargetResources[0].displayName)
| extend GroupId   = tostring(TargetResources[0].id)
| extend ActorUpn = tostring(InitiatedBy.user.userPrincipalName)
| extend ActorApp = tostring(InitiatedBy.app.displayName)
| extend Actor    = iff(isnotempty(ActorUpn), ActorUpn, ActorApp)
| extend ActorIp  = iff(
      isnotempty(tostring(InitiatedBy.user.ipAddress)),
      tostring(InitiatedBy.user.ipAddress),
      tostring(InitiatedBy.app.ipAddress))
| extend AccountName      = iff(ActorUpn has "@", tostring(split(ActorUpn, "@")[0]), Actor)
| extend AccountUPNSuffix = iff(ActorUpn has "@", tostring(split(ActorUpn, "@")[1]), "")
| project TimeGenerated, GroupName, GroupId, Actor, AccountName, AccountUPNSuffix, ActorIp, CorrelationId
| sort by TimeGenerated desc
```

### SIGMA

```yaml
title: Entra ID Role-Assignable Group Created
id: 2d8f6c4e-9a1b-4e7d-8c3a-5b6f0d2e9a47
status: test
tags:
    - attack.privilege-escalation
    - attack.persistence
    - attack.t1098.003
detection:
    selection:
        Category: GroupManagement
        OperationName: 'Add group'
        ModifiedProperty|contains: 'IsAssignableToRole'
        NewValue|contains: 'true'
    condition: selection
level: high
```

**Contributed**: [Azure-Sentinel#14789](https://github.com/Azure/Azure-Sentinel/pull/14789)

## False Positives

- IT or identity teams provisioning a new role-assignable group as part of a documented access model change
- Migration projects consolidating direct role assignments into group-based role assignment (a Microsoft-recommended pattern)

**Analyst note**: Confirm the creation aligns with a documented change and check which accounts currently hold Privileged Role Administrator. There is no legitimate reason for this event to occur frequently; treat unexplained matches as high priority regardless of who the actor appears to be.

## Investigation Steps

1. Identify the actor and confirm they hold Privileged Role Administrator or Global Administrator
2. Check for a documented change ticket for the new group
3. Watch the group for membership changes in the following hours and days (see [Member or owner added to a new role-assignable group](member-added-to-new-role-assignable-group.md))
4. Check whether a directory role is later assigned to the group
5. If unauthorized: delete the group before it is populated, or remove its role assignment and all members if it already has one

## References

- [Microsoft: Role-assignable groups](https://learn.microsoft.com/entra/identity/role-based-access-control/groups-concept)
- [MITRE T1098.003](https://attack.mitre.org/techniques/T1098/003/)
