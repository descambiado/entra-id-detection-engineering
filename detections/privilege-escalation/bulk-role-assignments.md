# Bulk Role Assignments in Short Window

## Technique
**MITRE ATT&CK**: [T1098.003 — Account Manipulation: Additional Cloud Credentials](https://attack.mitre.org/techniques/T1098/003/)  
**Tactic**: Persistence, Privilege Escalation

## What the attacker is doing

An attacker with privileged access rapidly assigns directory roles to multiple accounts they control before the intrusion is detected and remediated. The operational logic is simple: the attacker knows they have limited time before their access is revoked, so they maximize persistence by distributing privilege across as many accounts as possible in one burst.

This differs from deliberate administrative work, which involves individual, reviewed role assignments with context — a provisioning request, an approval ticket, a change window. Three or more role assignments within ten minutes to different accounts by the same actor is outside the normal operational pattern of human administrators.

The detection aggregates by actor and ten-minute time bucket, then enriches with the actor's most recent sign-in country to provide geographic context for triage.

## Detection

### KQL (Microsoft Sentinel)

```kql
let starttime = todatetime('{{StartTimeISO}}');
let endtime = todatetime('{{EndTimeISO}}');
let window = 10m;
let threshold = 3;
let RoleAssignments =
    AuditLogs
    | where TimeGenerated between (starttime .. endtime)
    | where OperationName =~ "Add member to role."
    | where Result =~ "success"
    | extend ActorUpn = tolower(tostring(parse_json(tostring(InitiatedBy.user)).userPrincipalName))
    | extend ActorApp = tostring(parse_json(tostring(InitiatedBy.app)).displayName)
    | extend ActorIp  = iff(
          isnotempty(tostring(parse_json(tostring(InitiatedBy.user)).ipAddress)),
          tostring(parse_json(tostring(InitiatedBy.user)).ipAddress),
          tostring(parse_json(tostring(InitiatedBy.app)).ipAddress))
    | extend Actor    = iff(isnotempty(ActorUpn), ActorUpn, ActorApp)
    | mv-expand TargetResource = TargetResources
    | where tostring(TargetResource.type) =~ "User"
    | extend TargetUpn = tostring(TargetResource.userPrincipalName)
    | where isnotempty(TargetUpn);
let BulkActors =
    RoleAssignments
    | summarize
        FirstAssignment = min(TimeGenerated),
        LastAssignment  = max(TimeGenerated),
        AssignedUsers   = make_set(TargetUpn),
        AssignmentCount = count(),
        ActorIp         = any(ActorIp)
        by Actor, bin(TimeGenerated, window)
    | where AssignmentCount >= threshold
    | extend WindowDurationSeconds = datetime_diff('second', LastAssignment, FirstAssignment);
let ActorSignIns =
    SigninLogs
    | where TimeGenerated between (starttime .. endtime)
    | where ResultType == 0
    | extend ActorUpn = tolower(UserPrincipalName)
    | summarize LastSignInTime = max(TimeGenerated) by ActorUpn, Location
    | summarize arg_max(LastSignInTime, Location) by ActorUpn
    | project ActorUpn, LastSignInCountry = Location;
BulkActors
| join kind=leftouter ActorSignIns on $left.Actor == $right.ActorUpn
| extend AccountName      = iff(Actor has "@", tostring(split(Actor, "@")[0]), Actor)
| extend AccountUPNSuffix = iff(Actor has "@", tostring(split(Actor, "@")[1]), "")
| project FirstAssignment, LastAssignment, WindowDurationSeconds, Actor,
    AccountName, AccountUPNSuffix, ActorIp, AssignmentCount, AssignedUsers, LastSignInCountry
| sort by FirstAssignment desc
```

**Contributed**: [Azure-Sentinel#14262](https://github.com/Azure/Azure-Sentinel/pull/14262)

## False Positives

- Automated provisioning systems performing bulk onboarding
- Help desk tools performing mass role setup during tenant restructuring
- Authorized migration workflows assigning roles to migrated accounts

**Analyst note**: Adjust the `threshold` variable (default: 3) upward in environments where automated provisioning regularly assigns roles in bulk. The `WindowDurationSeconds` column is key — a human administrator assigning 5 roles will have seconds or minutes between each assignment; an automated attack script will have sub-second gaps.

## Investigation Steps

1. Review `AssignedUsers` — are they all new accounts? Dormant accounts? Accounts created close together?
2. Check `LastSignInCountry` against expected actor location
3. Review `WindowDurationSeconds` — sub-10-second windows indicate scripted assignment
4. Check whether the actor account was itself recently created or had its own role elevated
5. For each assigned user, review subsequent privileged activity

## References

- [Microsoft: Azure AD roles reference](https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/permissions-reference)
- [MITRE T1098.003](https://attack.mitre.org/techniques/T1098/003/)
