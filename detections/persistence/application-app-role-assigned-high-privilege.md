# High-Privilege Application Role Assigned to Service Principal

## Technique
**MITRE ATT&CK**: [T1098.003 — Additional Cloud Roles](https://attack.mitre.org/techniques/T1098/003/), [T1528 — Steal Application Access Token](https://attack.mitre.org/techniques/T1528/)  
**Tactic**: Persistence, Credential Access

## What the attacker is doing

Application role assignments (also called app role grants) give a service principal tenant-wide access to a resource API without a signed-in user. When an attacker grants `Mail.ReadWrite` to a service principal they control, that SP can read every mailbox in the tenant — no user interaction, no MFA challenge, no Conditional Access enforcement.

This is the mechanism behind some of the most damaging Entra ID compromises:
- **Storm-0558** (2023): forged authentication tokens to access Exchange Online via application-level email access
- **Midnight Blizzard** (2024): added app role assignments to gain persistent Exchange and SharePoint access after compromising an OAuth application

The key distinction from delegated permissions (covered in the OAuth consent queries): application permissions are granted by an administrator, not consented to by a user. They appear in `AuditLogs` as `"Add app role assignment to service principal"` rather than `"Consent to application"`.

| Permission | What an attacker gets |
|-----------|----------------------|
| `Mail.ReadWrite` | Read, modify, delete every mailbox in the tenant |
| `Directory.ReadWrite.All` | Modify all users, groups, and organizational settings |
| `RoleManagement.ReadWrite.Directory` | Grant any directory role to any principal |
| `Application.ReadWrite.All` | Modify any app registration — can add backdoor credentials |
| `AppRoleAssignment.ReadWrite.All` | Self-grant any application permission |

## Why standard detections miss it

`"Add app role assignment to service principal"` is a legitimate operation in every tenant that uses Microsoft Graph API integrations. Alerting on it unconditionally produces noise. The signal is the specific permission being granted — high-risk application permissions are granted to a small set of legitimate enterprise applications and almost never as a routine operation.

## Detection

### KQL (Microsoft Sentinel)

```kql
let timeframe = 1d;
let HighRiskRoles = dynamic([
    "Mail.ReadWrite",
    "Mail.Send",
    "Files.ReadWrite.All",
    "Directory.ReadWrite.All",
    "RoleManagement.ReadWrite.Directory",
    "Application.ReadWrite.All",
    "AppRoleAssignment.ReadWrite.All",
    "User.ReadWrite.All",
    "full_access_as_app"
]);
AuditLogs
| where TimeGenerated >= ago(timeframe)
| where OperationName =~ "Add app role assignment to service principal"
| where Result =~ "success"
| extend ActorUpn = tostring(InitiatedBy.user.userPrincipalName)
| extend ActorApp = tostring(InitiatedBy.app.displayName)
| extend Actor    = iff(isnotempty(ActorUpn), ActorUpn, ActorApp)
| extend ActorIp  = iff(
      isnotempty(tostring(InitiatedBy.user.ipAddress)),
      tostring(InitiatedBy.user.ipAddress),
      tostring(InitiatedBy.app.ipAddress))
| extend TargetSpName = tostring(TargetResources[0].displayName)
| extend TargetSpId   = tostring(TargetResources[0].id)
| mv-expand ModProp = TargetResources[0].modifiedProperties
| where tostring(ModProp.displayName) =~ "AppRole.Value"
| extend AppRoleName = trim('"', tostring(ModProp.newValue))
| where AppRoleName in~ (HighRiskRoles)
| extend AccountName      = iff(Actor has "@", tostring(split(Actor, "@")[0]), Actor)
| extend AccountUPNSuffix = iff(Actor has "@", tostring(split(Actor, "@")[1]), "")
| project TimeGenerated, Actor, AccountName, AccountUPNSuffix, ActorIp,
          TargetSpName, TargetSpId, AppRoleName, CorrelationId
| sort by TimeGenerated desc
```

**Contributed**: [Azure/Azure-Sentinel#14281](https://github.com/Azure/Azure-Sentinel/pull/14281)

## False Positives

- Microsoft first-party service provisioning during product activation (Microsoft Sentinel, Defender for Cloud Apps, Purview)
- Legitimate enterprise applications requiring broad mailbox access (compliance archiving, legal hold, DLP platforms) deployed through a formal governance process
- Infrastructure-as-code pipelines provisioning new application integrations

**Analyst note**: Check when the target SP was registered. An SP registered in the last 48 hours receiving a high-privilege app role assignment is near-certain IOC. Also check the actor — Application Administrator role grants are scoped and auditable, but a non-admin account granting these permissions indicates a privilege escalation event upstream.

## Investigation Steps

1. Identify the target SP and when it was registered: `AuditLogs | where OperationName =~ "Add service principal" | where TargetResources[0].id == "<spid>"`
2. Check all permissions the SP holds — not just the one in this alert
3. Review sign-in activity for the SP in `AADServicePrincipalSignInLogs` immediately after the grant
4. Check the actor's recent AuditLog activity for other suspicious operations in the same session
5. If `AppRoleAssignment.ReadWrite.All` was granted: the SP can now self-grant any other permission — treat as critical

## References

- [Microsoft: Storm-0558 cloud email campaign analysis](https://www.microsoft.com/en-us/security/blog/2023/07/14/analysis-of-storm-0558-techniques-for-unauthorized-email-access/)
- [Microsoft: Midnight Blizzard January 2024](https://www.microsoft.com/en-us/security/blog/2024/01/25/midnight-blizzard-guidance-for-responders-on-nation-state-attack/)
- [MITRE T1098.003](https://attack.mitre.org/techniques/T1098/003/)
