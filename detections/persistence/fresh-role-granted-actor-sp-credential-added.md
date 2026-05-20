# Service Principal Credential Added by Freshly Privileged User

## Technique
**MITRE ATT&CK**: [T1098.001 — Additional Cloud Credentials](https://attack.mitre.org/techniques/T1098/001/)  
**Tactic**: Persistence

## What the attacker is doing

After gaining control of an account, an attacker's first move is often role elevation — granting the account Application Administrator or Global Administrator to legitimize subsequent operations. The credential addition that follows is the actual persistence mechanism, but by the time it fires, most detections have no memory of the role grant that preceded it by minutes or hours.

The attack chain:

1. Attacker compromises user account (phishing, token theft, password spray)
2. Attacker grants the account Application Administrator or Global Administrator via `Add member to role.`
3. Within the roleWindow (24h), attacker uses the freshly elevated account to add a `passwordCredential` or `keyCredential` to a high-value service principal
4. Attacker authenticates as the SP using the new credential, bypassing MFA and Conditional Access policies scoped to users

Both events are individually low-signal: role grants happen in normal IT operations, and SP credential additions are routine in DevOps workflows. The correlation is the signal.

This sequence appears in post-incident reporting for Midnight Blizzard and similar nation-state operator TTPs targeting Entra ID tenants.

## Why standard detections miss it

Detections watching `Add service principal credentials` see the same operation regardless of whether the actor has held the role for 3 years or 3 minutes. Without the temporal join against role grant history, the event is indistinguishable from a developer rotating a secret.

The gap is the absence of recency context for the actor's privilege. A user who received Application Administrator 20 minutes ago and immediately added credentials to a production SP is not behaving like a developer rotating a secret.

## Detection

### KQL (Microsoft Sentinel)

```kql
let timeframe = 1d;
let roleWindow = 24h;
let lookback = 7d;
let PrivilegedRoles = dynamic([
    "Application Administrator",
    "Cloud Application Administrator",
    "Global Administrator",
    "Privileged Role Administrator"
]);
let RecentRoleGrants =
    AuditLogs
    | where TimeGenerated >= ago(timeframe + lookback) and TimeGenerated < ago(0h)
    | where OperationName =~ "Add member to role."
    | where Result =~ "success"
    | extend NewRoleUser = tostring(TargetResources[0].userPrincipalName)
    | extend RoleName    = tostring(TargetResources[1].displayName)
    | where RoleName in~ (PrivilegedRoles)
    | where isnotempty(NewRoleUser)
    | project NewRoleUser, RoleName, RoleGrantedTime = TimeGenerated;
AuditLogs
| where TimeGenerated >= ago(timeframe)
| where OperationName in~ (
      "Add service principal credentials",
      "Update application - Certificates and secrets management"
  )
| where Result =~ "success"
| extend ActorUpn     = tostring(InitiatedBy.user.userPrincipalName)
| extend ActorApp     = tostring(InitiatedBy.app.displayName)
| extend Actor        = iff(isnotempty(ActorUpn), ActorUpn, ActorApp)
| extend ActorIp      = iff(
      isnotempty(tostring(InitiatedBy.user.ipAddress)),
      tostring(InitiatedBy.user.ipAddress),
      tostring(InitiatedBy.app.ipAddress))
| extend TargetSpName = tostring(TargetResources[0].displayName)
| extend TargetSpId   = tostring(TargetResources[0].id)
| where isnotempty(ActorUpn)
| join kind=inner RecentRoleGrants on $left.ActorUpn == $right.NewRoleUser
| where TimeGenerated >= RoleGrantedTime and TimeGenerated <= RoleGrantedTime + roleWindow
| extend AccountName      = iff(ActorUpn has "@", tostring(split(ActorUpn, "@")[0]), ActorUpn)
| extend AccountUPNSuffix = iff(ActorUpn has "@", tostring(split(ActorUpn, "@")[1]), "")
| project
    TimeGenerated,
    ActorUpn,
    AccountName,
    AccountUPNSuffix,
    RoleName,
    RoleGrantedTime,
    TargetSpName,
    TargetSpId,
    ActorIp,
    CorrelationId
| sort by TimeGenerated desc
```

**Contributed**: [Azure/Azure-Sentinel#14311](https://github.com/Azure/Azure-Sentinel/pull/14311)

## False Positives

- IT administrators who were legitimately promoted and immediately onboarded new applications as part of a planned project
- Automated provisioning pipelines that grant a service account elevated rights and then run credential rotation scripts in sequence
- Scheduled access reviews that result in role grants followed by SP maintenance

**Analyst note**: The most important variable is the target SP. An SP with broad Graph API permissions, production infrastructure access, or financial/HR data access warrants immediate escalation. SPs backing internal tooling with narrow scope can be triaged more slowly. Also check the role grant actor — if a different account granted the role than the one that added the credential, that is a stronger indicator of compromise.

## Investigation Steps

1. Confirm the role grant was expected: check change management records, Jira tickets, or ServiceNow for a task authorizing the role elevation
2. Identify the target SP's permissions: Entra ID portal > Enterprise applications > [SP name] > Permissions
3. Determine if this SP credential has been used: `AADServicePrincipalSignInLogs | where ServicePrincipalId == "<sp-id>" | where TimeGenerated > <credential-add-time> | order by TimeGenerated asc`
4. Identify who granted the role: `AuditLogs | where OperationName =~ "Add member to role." | where TargetResources[0].userPrincipalName =~ "<actor-upn>" | order by TimeGenerated desc`
5. Check whether the actor's account shows other anomalous activity in the same window: sign-ins from new locations, new MFA method registrations, other role or permission changes

## References

- [Microsoft: Application Administrator role definition](https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/permissions-reference#application-administrator)
- [Microsoft: Midnight Blizzard guidance](https://www.microsoft.com/en-us/security/blog/2024/01/25/midnight-blizzard-guidance-for-responders-on-nation-state-attack/)
- [MITRE T1098.001](https://attack.mitre.org/techniques/T1098/001/)
