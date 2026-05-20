# Service Principal Owner Added

## Technique
**MITRE ATT&CK**: [T1098.001 — Additional Cloud Credentials](https://attack.mitre.org/techniques/T1098/001/)  
**Tactic**: Persistence

## What the attacker is doing

An Entra ID service principal owner has full control over the SP object: they can add and remove password credentials, add and remove certificate credentials, and modify the SP's properties — all without holding a tenant-wide admin role. Ownership is granted at the object level and is not visible in the role assignment audit trail that most teams monitor.

In a post-compromise persistence chain:

1. Attacker compromises a user with Application Administrator or a scoped App Owner role
2. Attacker adds themselves (or a controlled identity) as owner of a high-value SP — one SP audit log entry, low noise
3. Attacker adds a new credential to the SP — now appears as a legitimate owner operation, not an anomalous actor
4. Attacker authenticates as the SP, bypassing MFA and Conditional Access

Step 2 sits in a detection gap between generic `Add owner` noise and the credential-focused detections that watch step 3. Catching ownership changes proactively provides a day of lead time before the SP is weaponized.

This is documented in post-incident analysis of Midnight Blizzard lateral movement within Microsoft's tenant.

## Why standard detections miss it

`Add owner to service principal` fires legitimately when developers add colleagues to SP objects they manage, when DevOps pipelines update app ownership during deployments, and when IT governance transfers object ownership between teams. Most detections either suppress the operation entirely or alert on it unconditionally at low severity — neither approach is useful.

The useful signal is ownership of high-privilege SPs. An SP with `Directory.ReadWrite.All`, `RoleManagement.ReadWrite.Directory`, or production infrastructure access getting a new owner outside business hours from an unfamiliar IP is the pattern to catch.

## Detection

### KQL (Microsoft Sentinel)

```kql
let timeframe = 1d;
AuditLogs
| where TimeGenerated >= ago(timeframe)
| where OperationName =~ "Add owner to service principal"
| where Result =~ "success"
| extend TargetSpName = tostring(TargetResources[0].displayName)
| extend TargetSpId   = tostring(TargetResources[0].id)
| extend NewOwnerUpn  = tostring(TargetResources[1].userPrincipalName)
| extend NewOwnerId   = tostring(TargetResources[1].id)
| extend ActorUpn     = tostring(InitiatedBy.user.userPrincipalName)
| extend ActorApp     = tostring(InitiatedBy.app.displayName)
| extend Actor        = iff(isnotempty(ActorUpn), ActorUpn, ActorApp)
| extend ActorIp      = iff(
      isnotempty(tostring(InitiatedBy.user.ipAddress)),
      tostring(InitiatedBy.user.ipAddress),
      tostring(InitiatedBy.app.ipAddress))
| extend AccountName      = iff(NewOwnerUpn has "@",
      tostring(split(NewOwnerUpn, "@")[0]), NewOwnerUpn)
| extend AccountUPNSuffix = iff(NewOwnerUpn has "@",
      tostring(split(NewOwnerUpn, "@")[1]), "")
| project
    TimeGenerated,
    TargetSpName,
    TargetSpId,
    NewOwnerUpn,
    AccountName,
    AccountUPNSuffix,
    NewOwnerId,
    Actor,
    ActorIp,
    CorrelationId
| sort by TimeGenerated desc
```

**Contributed**: [Azure/Azure-Sentinel#14307](https://github.com/Azure/Azure-Sentinel/pull/14307)

## False Positives

- Developers adding team members as co-owners of SPs they manage during normal onboarding
- IT governance transfers during application ownership handoffs between teams
- Automated provisioning pipelines that assign SP ownership as part of deployment

**Analyst note**: Priority-triage based on the target SP's permissions. SPs with `Directory.ReadWrite.All`, `RoleManagement.ReadWrite.Directory`, `Application.ReadWrite.All`, or access to production infrastructure warrant immediate investigation. Check whether the new owner has previously performed any operations on this SP, and cross-reference with `AADServicePrincipalSignInLogs` to see if a sign-in using new credentials follows within hours.

## Investigation Steps

1. Check what permissions the target SP holds: review App Roles and OAuth2PermissionGrants in Entra ID
2. Determine whether the new owner has legitimately managed this SP before: `AuditLogs | where OperationName in~ ("Add service principal credentials", "Update application") | where InitiatedBy.user.userPrincipalName =~ "<new-owner-upn>"`
3. Check if a credential addition followed: `AuditLogs | where OperationName =~ "Add service principal credentials" | where TargetResources[0].id == "<sp-id>" | where TimeGenerated > <ownership-change-time>`
4. Check for new sign-ins as the SP: `AADServicePrincipalSignInLogs | where ServicePrincipalId == "<sp-id>" | where TimeGenerated > <ownership-change-time>`

## References

- [Microsoft: Manage service principal ownership](https://learn.microsoft.com/en-us/entra/identity/enterprise-apps/assign-app-owners)
- [Microsoft: Midnight Blizzard guidance](https://www.microsoft.com/en-us/security/blog/2024/01/25/midnight-blizzard-guidance-for-responders-on-nation-state-attack/)
- [MITRE T1098.001](https://attack.mitre.org/techniques/T1098/001/)
