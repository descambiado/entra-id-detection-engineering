# OAuth Consent to High-Risk Permission Scope (90-Day Baseline)

## Technique
**MITRE ATT&CK**: [T1528 - Steal Application Access Token](https://attack.mitre.org/techniques/T1528/)  
**Tactic**: Credential Access, Persistence

## What the attacker is doing

This detection targets the same illicit OAuth consent vector as the base detection, but adds a 90-day novelty filter: the query only surfaces consent events for apps that have **never previously received consent from any user in the tenant**. In an established tenant, most OAuth consent events are benign - employees consenting to apps the IT team has already approved or that colleagues have used before. The attacker's freshly registered app has zero prior consent history.

The combination of a high-risk permission scope AND a first-time-seen app in the tenant sharply reduces the false positive rate and prioritizes events that warrant immediate investigation.

## Why this complements the base detection

The base detection (`OAuthConsentToHighRiskPermission`) fires on all high-risk scope grants regardless of the app's history. That is intentional - a known-bad app being granted access a second time is also worth flagging. This variant is the higher-fidelity alert: first-seen app plus dangerous scope is the canonical illicit consent grant pattern.

In practice, analyst workflow is:

1. This detection fires -> nearly always investigate immediately (very low FP rate)
2. Base detection fires with no match here -> check if app is known/approved -> lower urgency

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
let KnownApps =
    AuditLogs
    | where TimeGenerated >= ago(timeframe + lookback) and TimeGenerated < ago(timeframe)
    | where OperationName =~ "Consent to application"
    | extend AppId = tostring(TargetResources[0].id)
    | distinct AppId;
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
| where tostring(ModProp.displayName) =~ "ConsentAction.Permissions"
| extend GrantedPermissions = tostring(ModProp.newValue)
| where GrantedPermissions has_any (HighRiskScopes)
| join kind=leftanti KnownApps on AppId
| extend AccountName      = iff(Actor has "@", tostring(split(Actor, "@")[0]), Actor)
| extend AccountUPNSuffix = iff(Actor has "@", tostring(split(Actor, "@")[1]), "")
| project TimeGenerated, AppName, AppId, GrantedPermissions, Actor,
          AccountName, AccountUPNSuffix, ActorIp, CorrelationId
| sort by TimeGenerated desc
```

**Contributed**: [Azure-Sentinel#14276](https://github.com/Azure/Azure-Sentinel/pull/14276)

## False Positives

- A new enterprise application being piloted for the first time, requiring broad permissions before a formal approval process has been run
- Tenants without a 90-day history in the workspace will treat all consent events as first-seen

**Analyst note**: Cross-check the app's `AppId` against the Entra ID Enterprise Applications list. An external app (not registered in your tenant) consenting for the first time with Mail or Directory write access is a near-certain illicit consent grant. Internal apps first-seen in the last 7 days warrant equal scrutiny.

## Investigation Steps

1. Confirm the app registration: `AuditLogs | where OperationName =~ "Add service principal" | where TargetResources[0].id == "<AppId>"`
2. Check how many users have consented: look for other `Consent to application` events for the same `AppId`
3. Check post-consent sign-in activity from `AppId` in `AADServicePrincipalSignInLogs`
4. Review what resources the app has accessed since consent (Unified Audit Log, SharePoint/Exchange logs)
5. Revoke consent: Entra ID portal > Enterprise Applications > [app] > Permissions > Revoke admin consent

## References

- [Microsoft: Detect and remediate illicit consent grants](https://learn.microsoft.com/en-us/microsoft-365/security/office-365-security/detect-and-remediate-illicit-consent-grants)
- [Storm-0558: Microsoft MSRC blog](https://msrc.microsoft.com/blog/2023/07/microsoft-mitigates-china-based-threat-actor-storm-0558-targeting-of-customer-email/)
- [MITRE T1528](https://attack.mitre.org/techniques/T1528/)
