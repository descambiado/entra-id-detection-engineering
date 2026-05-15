# OAuth Consent to High-Risk Permission

## Technique
**MITRE ATT&CK**: [T1528 — Steal Application Access Token](https://attack.mitre.org/techniques/T1528/)  
**Tactic**: Credential Access, Initial Access

## What the attacker is doing

An attacker registers a malicious OAuth application in their own tenant and sends a crafted consent URL to a target user — typically via phishing email or a compromised website. When the user clicks "Accept", they grant the attacker's app delegated access to their mailbox, files, or directory without ever entering their password again.

The attacker now has a persistent OAuth access token that:
- Survives password resets (tokens are issued, not credential-based after consent)
- Works from any IP with no MFA challenge
- Is invisible to most MFA and Conditional Access controls
- Can be refreshed indefinitely if the refresh token is not revoked

Dangerous permissions targeted in real campaigns:
| Permission | What an attacker can do |
|-----------|------------------------|
| `Mail.ReadWrite` | Read, move, delete all email — exfil and cover tracks |
| `Mail.Send` | Send as the victim — BEC, internal phishing |
| `Files.ReadWrite.All` | Full access to all SharePoint and OneDrive files |
| `full_access_as_app` | Exchange full mailbox access |
| `Directory.ReadWrite.All` | Modify users, groups, and roles |
| `RoleManagement.ReadWrite.Directory` | Grant any directory role to any user |

## Why standard detections miss it

The existing broad end-user consent rule (`azure_app_end_user_consent`) fires on **every** consent event at low severity — including employees installing legitimate productivity apps. Analysts stop paying attention to low-severity consent alerts within days of deployment.

This detection fires only when the consented scope includes a permission from the high-risk list, raising severity to high and cutting noise by 95%+ in most environments.

## Detection

### KQL (Microsoft Sentinel)

```kql
let timeframe = 1d;
let lookback = 90d;
let HighRiskScopes = dynamic([
    "RoleManagement.ReadWrite.Directory",
    "Application.ReadWrite.All",
    "AppRoleAssignment.ReadWrite.All",
    "Directory.ReadWrite.All",
    "User.ReadWrite.All",
    "Mail.ReadWrite",
    "Mail.Send",
    "Files.ReadWrite.All",
    "full_access_as_app"
]);
let KnownAppSet = toscalar(
    AuditLogs
    | where TimeGenerated >= ago(timeframe + lookback) and TimeGenerated < ago(timeframe)
    | where OperationName =~ "Consent to application"
    | extend AppId = tostring(TargetResources[0].id)
    | summarize make_set(AppId)
);
AuditLogs
| where TimeGenerated >= ago(timeframe)
| where OperationName =~ "Consent to application"
| where Result =~ "success"
| extend AppId    = tostring(TargetResources[0].id)
| extend AppName  = tostring(TargetResources[0].displayName)
| extend ActorUpn = tostring(InitiatedBy.user.userPrincipalName)
| extend ActorApp = tostring(InitiatedBy.app.displayName)
| extend Actor    = iff(isnotempty(ActorUpn), ActorUpn, ActorApp)
| extend ActorIp  = iff(
      isnotempty(tostring(InitiatedBy.user.ipAddress)),
      tostring(InitiatedBy.user.ipAddress),
      tostring(InitiatedBy.app.ipAddress))
| mv-expand ModProp = TargetResources[0].modifiedProperties
| where tostring(ModProp.displayName) =~ "ConsentContext.Permissions"
| extend GrantedPermissions = tostring(ModProp.newValue)
| where GrantedPermissions has_any (HighRiskScopes)
| extend IsNewApp = not(set_has_element(KnownAppSet, AppId))
| extend AccountName      = iff(Actor has "@", tostring(split(Actor, "@")[0]), Actor)
| extend AccountUPNSuffix = iff(Actor has "@", tostring(split(Actor, "@")[1]), "")
| project TimeGenerated, AppName, AppId, GrantedPermissions, Actor,
          AccountName, AccountUPNSuffix, ActorIp, IsNewApp, CorrelationId
| sort by TimeGenerated desc
```

### SIGMA

```yaml
title: End User Consent to Application With High-Risk OAuth Permission
id: b6b198d5-dbe4-473e-8ec4-51b11e9ab22b
related:
    - id: 9b2cc4c4-2ad4-416d-8e8e-ee6aa6f5035a
      type: similar
status: test
tags:
    - attack.credential-access
    - attack.initial-access
    - attack.t1528
detection:
    selection_operation:
        OperationName: 'Consent to application'
    selection_scope:
        TargetResources|contains:
            - 'Mail.ReadWrite'
            - 'Files.ReadWrite.All'
            - 'Mail.Send'
            - 'MailboxSettings.ReadWrite'
            - 'full_access_as_app'
            - 'EWS.AccessAsUser.All'
            - 'Directory.ReadWrite.All'
            - 'RoleManagement.ReadWrite.Directory'
    condition: selection_operation and selection_scope
level: high
```

**Contributed**: [SigmaHQ/sigma#6012](https://github.com/SigmaHQ/sigma/pull/6012)

## False Positives

- Enterprise applications legitimately requiring broad mailbox access (e.g., compliance archiving tools, legal hold platforms)
- IT-approved productivity integrations reviewed through a formal application governance process

**Analyst note**: Always check if the app is registered in your tenant or is a third-party app. Internal apps consenting to broad permissions are lower risk than external ones. Check the app's first-seen date in Entra ID — apps registered in the last 7 days consenting to these scopes are near-certain IOCs.

## Investigation Steps

1. Identify the consenting user and the app's `ServicePrincipalId`
2. Check the app's registration date: `AuditLogs | where OperationName =~ "Add service principal" | where TargetResources[0].id == "<spid>"`
3. Check how many users in the tenant have consented to the same app
4. Review post-consent activity: email forwarding rules, file access in Unified Audit Log
5. Revoke consent via Entra ID > Enterprise Applications > Permissions if suspicious

## References

- [Microsoft: Detect and remediate illicit consent grants](https://learn.microsoft.com/en-us/microsoft-365/security/office-365-security/detect-and-remediate-illicit-consent-grants)
- [MITRE T1528](https://attack.mitre.org/techniques/T1528/)
