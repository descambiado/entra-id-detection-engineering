# Break-Glass Account Role or Group Membership Changed

## Technique
**MITRE ATT&CK**: [T1098.003 - Account Manipulation: Additional Cloud Roles](https://attack.mitre.org/techniques/T1098/003/)
**Tactic**: Persistence, Privilege Escalation

## What the attacker is doing

A break-glass account earns its trust from being boring: it is provisioned once with a single static directory role, usually Global Administrator, no group memberships, and no further changes until the next scheduled test. That predictability is exactly what lets an analyst treat every membership change on the account as significant rather than trying to separate signal from routine administrative noise.

Two paths lead to the same outcome and both are covered here. A direct role assignment or removal shows up as an "Add member to role" or "Remove member from role" event with the break-glass account as the target. A group-mediated change, where the account is added to or removed from a group, including a role-assignable group (see [Role-assignable group created](../privilege-escalation/role-assignable-group-created.md)), shows up as a group membership event instead. An attacker who quietly folds a break-glass account into a role-assignable group inherits whatever role that group holds without ever generating a role-assignment event against the account directly, which is precisely why both paths need to be watched together.

## Why standard detections miss it

Role-change monitoring and group-membership monitoring are typically separate detections, and neither is normally scoped down to a tiny, known set of accounts where any match is meaningful. Watching both paths together, scoped to the break-glass watchlist specifically, is what turns two individually noisy event types into a near-zero-false-positive signal.

## Detection

### KQL (Microsoft Sentinel)

```kql
let starttime = todatetime('{{StartTimeISO}}');
let endtime = todatetime('{{EndTimeISO}}');
let BreakGlassAccounts = (
    _GetWatchlist('BreakGlassAccounts')
    | project AccountUPN = tolower(tostring(SearchKey))
);
let RoleChangesBase = materialize(
    AuditLogs
    | where TimeGenerated between (starttime .. endtime)
    | where Category =~ "RoleManagement"
    | where OperationName in~ ("Add member to role", "Add member to role.", "Remove member from role", "Remove member from role.")
    | where Result =~ "success"
    | mv-apply TargetResource = TargetResources on (
          where TargetResource.type =~ "User"
          | extend TargetUpn = tolower(tostring(TargetResource.userPrincipalName)),
                   RoleProps = TargetResource.modifiedProperties
      )
    | where TargetUpn in (BreakGlassAccounts)
    | extend RowId      = new_guid()
    | extend ChangeType = iff(OperationName has "Add", "RoleAdded", "RoleRemoved")
    | extend ActorUpn = tostring(InitiatedBy.user.userPrincipalName)
    | extend ActorApp = tostring(InitiatedBy.app.displayName)
    | extend Actor    = iff(isnotempty(ActorUpn), ActorUpn, ActorApp)
    | extend ActorIp  = iff(
          isnotempty(tostring(InitiatedBy.user.ipAddress)),
          tostring(InitiatedBy.user.ipAddress),
          tostring(InitiatedBy.app.ipAddress))
);
let RoleNames =
    RoleChangesBase
    | project RowId, RoleProps
    | mv-expand ModProp = RoleProps
    | where tostring(ModProp.displayName) =~ "Role.DisplayName"
    | project RowId, ChangedObject = trim('"', tostring(coalesce(ModProp.newValue, ModProp.oldValue)));
let RoleChanges =
    RoleChangesBase
    | join kind=leftouter RoleNames on RowId
    | extend ChangedObject = iff(isempty(ChangedObject), "(role name unavailable)", ChangedObject)
    | project TimeGenerated, OperationName, ChangeType, ChangedObject, TargetUpn, Actor, ActorIp, CorrelationId;
let GroupChangesBase = materialize(
    AuditLogs
    | where TimeGenerated between (starttime .. endtime)
    | where Category =~ "GroupManagement"
    | where OperationName in~ ("Add member to group", "Add owner to group", "Remove member from group", "Remove owner from group")
    | where Result =~ "success"
    | extend ActorUpn = tostring(InitiatedBy.user.userPrincipalName)
    | extend ActorApp = tostring(InitiatedBy.app.displayName)
    | extend Actor    = iff(isnotempty(ActorUpn), ActorUpn, ActorApp)
    | extend ActorIp  = iff(
          isnotempty(tostring(InitiatedBy.user.ipAddress)),
          tostring(InitiatedBy.user.ipAddress),
          tostring(InitiatedBy.app.ipAddress))
    | extend ChangeType = case(
          OperationName has_cs "Add" and OperationName has_cs "owner", "GroupOwnerAdded",
          OperationName has_cs "Add", "GroupMemberAdded",
          OperationName has_cs "owner", "GroupOwnerRemoved",
          "GroupMemberRemoved")
    | mv-apply TargetResource = TargetResources on (
          where TargetResource.type =~ "User"
          | extend TargetUpn  = tolower(tostring(TargetResource.userPrincipalName)),
                   Properties = TargetResource.modifiedProperties
      )
    | where TargetUpn in (BreakGlassAccounts)
    | extend RowId = new_guid()
);
let GroupNames =
    GroupChangesBase
    | project RowId, Properties
    | mv-expand Property = Properties
    | where tostring(Property.displayName) =~ "Group.DisplayName"
    | project RowId, ChangedObject = trim('"', tostring(coalesce(Property.newValue, Property.oldValue)));
let GroupChanges =
    GroupChangesBase
    | join kind=leftouter GroupNames on RowId
    | extend ChangedObject = iff(isempty(ChangedObject), "(group name unavailable)", ChangedObject)
    | project TimeGenerated, OperationName, ChangeType, ChangedObject, TargetUpn, Actor, ActorIp, CorrelationId;
union RoleChanges, GroupChanges
| extend AccountName      = tostring(split(TargetUpn, "@")[0])
| extend AccountUPNSuffix = tostring(split(TargetUpn, "@")[1])
| project
    TimeGenerated, OperationName, ChangeType, ChangedObject, TargetUpn,
    AccountName, AccountUPNSuffix, Actor, ActorIp, CorrelationId
| sort by TimeGenerated desc
```

`materialize()` is required on both `RoleChangesBase` and `GroupChangesBase`: each is referenced twice below (once to build the name lookup, once as the left side of the join back to it), and without pinning the result, the two references would each re-evaluate `new_guid()` independently, so the `RowId` used to join would never match itself. The account and the changed role/group are read from whichever `TargetResources` entry describes the user, not from a fixed array index, since an audit event can carry multiple resources and their ordering is not guaranteed. This query, like the other two in this pack, depends on a watchlist named `BreakGlassAccounts` whose `SearchKey` column holds the user principal names of the tenant's designated emergency access accounts.

**Contributed**: [Azure-Sentinel#14948](https://github.com/Azure/Azure-Sentinel/pull/14948)

## False Positives

- The organization's scheduled break-glass access test, if it includes a deliberate role or group re-assignment step
- A documented emergency-access review that restructures how the account's access is granted

**Analyst note**: Every match should be checked against the change calendar for a documented emergency-access review or test. A change with no corresponding record, an unfamiliar actor, or one that lands close in time to a sign-in or credential change on the same account (see the two companion queries in this pack) should be treated as high priority.

## Investigation Steps

1. Check the change calendar for a documented, in-progress break-glass test or review
2. Identify the actor and the specific role or group involved
3. If a group-mediated change: check whether the group is role-assignable and what role it holds
4. Check the two companion break-glass queries for a concurrent sign-in or credential change
5. If unauthorized: revert the role/group change, rotate the account's credentials, and review who had access to make the change

## References

- [Microsoft: Manage emergency access accounts](https://learn.microsoft.com/entra/identity/role-based-access-control/security-emergency-access)
- [Microsoft: Role-assignable groups](https://learn.microsoft.com/entra/identity/role-based-access-control/groups-concept)
- [MITRE T1098.003](https://attack.mitre.org/techniques/T1098/003/)
