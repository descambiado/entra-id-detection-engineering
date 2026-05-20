# OAuth Application Redirect URI Modified

## Technique
**MITRE ATT&CK**: [T1528 — Steal Application Access Token](https://attack.mitre.org/techniques/T1528/)  
**Tactic**: Credential Access, Persistence

## What the attacker is doing

In the OAuth 2.0 authorization code flow, after a user authenticates and consents, the identity provider redirects the browser to a URI specified in the authorization request — delivering the authorization code to that endpoint. The delivered code can be exchanged for an access token and refresh token.

An app registration's `ReplyUrls` (redirect URIs) field defines which URIs are valid redirect destinations. If an attacker adds a URI they control to an existing trusted app registration, they can craft authorization requests pointing to their URI. When a user authenticates through that app's normal login flow, the authorization code lands at the attacker's endpoint instead of the app's legitimate backend.

This requires:
- An attacker with Application Administrator, Cloud Application Administrator, or owner of the target app registration
- A target app that users regularly authenticate against (high-value: Exchange Online, SharePoint, or any internal app with Mail/Files scopes)

No new app registration is created. The attack hijacks an existing, trusted app that users have already consented to, bypassing first-seen-app and consent-event detections entirely.

## Why standard detections miss it

Most OAuth-focused detections watch for `Consent to application` events or new app registrations. A redirect URI addition produces no consent event — the app is already consented. `Update application` fires constantly in any active tenant as developers push changes, so it's typically suppressed or tiered low. Filtering specifically on the `ReplyUrls` property change isolates the relevant subset.

## Detection

### KQL (Microsoft Sentinel)

```kql
let timeframe = 1d;
AuditLogs
| where TimeGenerated >= ago(timeframe)
| where OperationName =~ "Update application"
| where Result =~ "success"
| mv-expand ModProp = TargetResources[0].modifiedProperties
| where tostring(ModProp.displayName) =~ "ReplyUrls"
| extend OldReplyUrls = tostring(ModProp.oldValue)
| extend NewReplyUrls = tostring(ModProp.newValue)
| extend AppName = tostring(TargetResources[0].displayName)
| extend AppId   = tostring(TargetResources[0].id)
| extend ActorUpn = tostring(InitiatedBy.user.userPrincipalName)
| extend ActorApp = tostring(InitiatedBy.app.displayName)
| extend Actor    = iff(isnotempty(ActorUpn), ActorUpn, ActorApp)
| extend ActorIp  = iff(
      isnotempty(tostring(InitiatedBy.user.ipAddress)),
      tostring(InitiatedBy.user.ipAddress),
      tostring(InitiatedBy.app.ipAddress))
| extend AccountName      = iff(ActorUpn has "@",
      tostring(split(ActorUpn, "@")[0]), Actor)
| extend AccountUPNSuffix = iff(ActorUpn has "@",
      tostring(split(ActorUpn, "@")[1]), "")
| project
    TimeGenerated,
    AppName,
    AppId,
    OldReplyUrls,
    NewReplyUrls,
    Actor,
    AccountName,
    AccountUPNSuffix,
    ActorIp,
    CorrelationId
| sort by TimeGenerated desc
```

**Contributed**: [Azure/Azure-Sentinel#14307](https://github.com/Azure/Azure-Sentinel/pull/14307)

## False Positives

- Developers adding localhost redirect URIs for local development (`http://localhost:*`)
- CI/CD pipelines updating production redirect URIs during deployment
- Application owners adding redirect URIs for new platform support (e.g., adding a mobile app callback)

**Analyst note**: Compare `OldReplyUrls` and `NewReplyUrls` to identify which URIs were added. Localhost URIs and URIs matching the organization's own domains are low risk. URIs pointing to external domains, URL shorteners, or hosting providers (ngrok, Vercel, cloud VMs) warrant immediate investigation. Also check what scopes the modified app holds — apps with `Mail.ReadWrite`, `Files.ReadWrite.All`, or `full_access_as_app` are the highest-value targets for this attack.

## Investigation Steps

1. Diff `OldReplyUrls` and `NewReplyUrls` to identify the newly added URIs
2. Geolocate and WHOIS the new URI's domain — hosting providers and recently registered domains are strong IOCs
3. Check whether the actor recently acquired access to the app: `AuditLogs | where OperationName =~ "Add owner to application" | where TargetResources[0].id == "<app-id>"`
4. Review the app's permissions: check App Roles and OAuth2PermissionGrants in Entra ID
5. If confirmed malicious: remove the redirect URI via Entra ID > App registrations, revoke all tokens issued to the app, and review sign-in logs for the access pattern

## References

- [Microsoft: Redirect URI security considerations](https://learn.microsoft.com/en-us/entra/identity-platform/reply-url)
- [MITRE T1528](https://attack.mitre.org/techniques/T1528/)
