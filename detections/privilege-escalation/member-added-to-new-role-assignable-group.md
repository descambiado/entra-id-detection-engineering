# Member or Owner Added to a New Role-Assignable Group

## Technique
**MITRE ATT&CK**: [T1098.003 - Account Manipulation: Additional Cloud Roles](https://attack.mitre.org/techniques/T1098/003/)
**Tactic**: Privilege Escalation, Persistence

## What the attacker is doing

This is the companion query to [Role-assignable group created](role-assignable-group-created.md). Group role-assignability can only be set at creation time, not added to an existing group, so this chains two individually low-signal events into a high-confidence indicator of privilege escalation: an attacker who holds Privileged Role Administrator or Global Administrator access creates a role-assignable group, then immediately adds an account, often their own, or a service principal, as a member or owner.

That account inherits any directory role later assigned to the group without ever generating an "Add member to role" audit event for itself, since the role is granted to the group as a whole.

## Why standard detections miss it

Role-assignment monitoring watches `Add member to role` events against user or service principal targets. An account added to a role-assignable group never appears as the target of that operation; the group does, potentially much earlier or later, and only if the group is watched directly. This query closes that gap by correlating group creation with membership changes in a short window, instead of relying on the eventual role assignment to surface.

## Detection

### KQL (Microsoft Sentinel)

```kql
let timeframe = 1d;
let creationLookback = 14d;
let window = 24h;
let RecentlyCreatedRoleAssignableGroups =
    AuditLogs
    | where TimeGenerated >= ago(timeframe + creationLookback) and TimeGenerated < ago(0h)
    | where Category =~ "GroupManagement"
    | where OperationName =~ "Add group"
    | where Result =~ "success"
    | mv-expand ModProp = TargetResources[0].modifiedProperties
    | extend PropName = tostring(ModProp.displayName)
    | extend NewValue = tostring(ModProp.newValue)
    | where PropName has "IsAssignableToRole" or NewValue has "isAssignableToRole"
    | where NewValue has "true"
    | extend GroupId = tolower(tostring(TargetResources[0].id))
    | where isnotempty(GroupId)
    | project GroupId, CreationTime = TimeGenerated;
AuditLogs
| where TimeGenerated >= ago(timeframe)
| where Category =~ "GroupManagement"
| where OperationName in~ ("Add member to group", "Add owner to group")
| where Result =~ "success"
| extend ActorUpn = tostring(InitiatedBy.user.userPrincipalName)
| extend ActorApp = tostring(InitiatedBy.app.displayName)
| extend Actor    = iff(isnotempty(ActorUpn), ActorUpn, ActorApp)
| extend ActorIp  = iff(
      isnotempty(tostring(InitiatedBy.user.ipAddress)),
      tostring(InitiatedBy.user.ipAddress),
      tostring(InitiatedBy.app.ipAddress))
| mv-apply TargetResource = TargetResources on (
      where TargetResource.type =~ "User"
      | extend AddedUpn = tostring(TargetResource.userPrincipalName),
               AddedId  = tostring(TargetResource.id),
               Properties = TargetResource.modifiedProperties
  )
| mv-apply Property = Properties on (
      where Property.displayName =~ "Group.ObjectID"
      | extend GroupId = tolower(trim('"', tostring(Property.newValue)))
  )
| mv-apply Property = Properties on (
      where Property.displayName =~ "Group.DisplayName"
      | extend GroupName = trim('"', tostring(Property.newValue))
  )
| where isnotempty(GroupId)
| join kind=inner RecentlyCreatedRoleAssignableGroups on GroupId
| where TimeGenerated >= CreationTime and TimeGenerated <= CreationTime + window
| extend AccountName      = iff(ActorUpn has "@", tostring(split(ActorUpn, "@")[0]), Actor)
| extend AccountUPNSuffix = iff(ActorUpn has "@", tostring(split(ActorUpn, "@")[1]), "")
| project
    TimeGenerated, OperationName, GroupName, GroupId, CreationTime,
    AddedUpn, AddedId, Actor, AccountName, AccountUPNSuffix, ActorIp, CorrelationId
| sort by TimeGenerated desc
```

The group identity for "Add member to group" and "Add owner to group" events is read from the `Group.ObjectID` and `Group.DisplayName` modifiedProperties on the added principal's `TargetResources` entry rather than from a fixed array index, since `TargetResources` ordering is not guaranteed to place the group first.

### SIGMA

```yaml
title: Member or Owner Added to a Newly Created Role-Assignable Group
id: 7c1e9b5a-3f2d-4a8e-b6c1-9d4a2e7f5c30
status: test
tags:
    - attack.privilege-escalation
    - attack.persistence
    - attack.t1098.003
detection:
    selection:
        Category: GroupManagement
        OperationName:
            - 'Add member to group'
            - 'Add owner to group'
    condition: selection
level: high
falsepositives:
    - Requires correlation against role-assignable group creation within the prior 24 hours; a standalone match on this selection is not high-confidence by itself
```

**Contributed**: [Azure-Sentinel#14789](https://github.com/Azure/Azure-Sentinel/pull/14789)

## False Positives

- Legitimate onboarding into a newly created role-assignable group as part of a documented access model rollout
- Automated provisioning that creates a group and populates it as a single change

**Analyst note**: Investigate whether the creation and the membership change were part of the same documented change, whether the added identity already holds other privileged access, and whether the group is subsequently assigned a directory role.

## Investigation Steps

1. Confirm the group was created within the correlation window and check the creator's identity
2. Identify the added account or service principal and whether it already holds privileged access elsewhere
3. Check for a documented change ticket covering both the creation and the membership change
4. Check whether a directory role has been or is later assigned to the group
5. If unauthorized: remove the member/owner, review the group for further changes, and audit the actor's other recent group and role activity

## References

- [Microsoft: Role-assignable groups](https://learn.microsoft.com/entra/identity/role-based-access-control/groups-concept)
- [MITRE T1098.003](https://attack.mitre.org/techniques/T1098/003/)
