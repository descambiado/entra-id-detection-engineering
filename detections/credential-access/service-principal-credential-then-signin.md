# Service Principal Credential Addition Followed by Immediate Sign-In

## Technique
**MITRE ATT&CK**: [T1098.001 — Additional Cloud Credentials](https://attack.mitre.org/techniques/T1098/001/), [T1528 — Steal Application Access Token](https://attack.mitre.org/techniques/T1528/)  
**Tactic**: Persistence, Credential Access

## What the attacker is doing

When an attacker compromises an account with Application Administrator or Cloud Application Administrator privileges, they can add a new client secret or certificate to any service principal in the tenant. This gives them a persistent credential that survives password resets on the compromised user account and is not bound by MFA or Conditional Access policies.

The operational pattern is tight: add credentials, sign in with the SP within minutes, begin exfiltration or lateral movement before the added credential is noticed. This is documented behavior from Midnight Blizzard (2024) and the earlier SolarWinds campaign infrastructure.

The existing `DormantServicePrincipalUpdateCredsandLogsIn` detection in Azure-Sentinel requires the SP to be dormant — no sign-in activity in the prior 14 days. Midnight Blizzard specifically targeted active, well-known SPs (Microsoft first-party apps and established third-party integrations) because those have broad existing permissions and are less likely to trigger dormancy alerts.

## Why standard detections miss it

- Credential addition to a service principal is a routine DevOps operation in any tenant that manages app integrations via infrastructure-as-code
- SP sign-ins from new IPs are common when deploying to new environments
- The individual events are not suspicious — only the sub-30-minute correlation window is the signal

## Detection

### KQL (Microsoft Sentinel)

```kql
let timeframe = 1d;
let correlationWindow = 30m;
let CredAdded =
    AuditLogs
    | where TimeGenerated >= ago(timeframe)
    | where OperationName in~ (
          "Add service principal credentials",
          "Update application - Certificates and secrets management"
      )
    | where Result =~ "success"
    | project
        CredAddedTime      = TimeGenerated,
        SpId               = tostring(TargetResources[0].id),
        SpName             = tostring(TargetResources[0].displayName),
        ActorUpn           = tostring(InitiatedBy.user.userPrincipalName),
        ActorApp           = tostring(InitiatedBy.app.displayName),
        AuditCorrelationId = CorrelationId;
AADServicePrincipalSignInLogs
| where TimeGenerated >= ago(timeframe)
| where ResultType == 0
| join kind=inner CredAdded on $left.ServicePrincipalId == $right.SpId
| where TimeGenerated between (CredAddedTime .. (CredAddedTime + correlationWindow))
| extend Actor = iff(isnotempty(ActorUpn), ActorUpn, ActorApp)
| project
    TimeGenerated,
    ServicePrincipalId,
    ServicePrincipalName = SpName,
    AppId,
    IPAddress,
    Location,
    ResourceDisplayName,
    CredAddedTime,
    Actor,
    AuditCorrelationId,
    SignInCorrelationId  = CorrelationId
| sort by TimeGenerated desc
```

**Contributed**: [Azure/Azure-Sentinel#14299](https://github.com/Azure/Azure-Sentinel/pull/14299)

## False Positives

- Automated CI/CD pipelines that rotate client secrets and immediately test connectivity
- Infrastructure provisioning scripts that create SP credentials and validate them in the same run
- Microsoft first-party service provisioning during product activation

**Analyst note**: Check whether the sign-in IP belongs to known CI/CD infrastructure. An SP that has only ever signed in from a fixed cloud egress IP and suddenly signs in from a residential or VPS address within 30 minutes of a credential change is a strong IOC.

## Investigation Steps

1. Identify who added the credentials: check `Actor` field — if it is an application identity rather than a named user, investigate what application performed the operation
2. Check all permissions held by the SP: `AuditLogs | where OperationName =~ "Add app role assignment to service principal" | where TargetResources[0].id == "<spid>"`
3. Review `AADServicePrincipalSignInLogs` for the SP in the 24 hours following the credential addition
4. Check whether the SP already had high-privilege permissions before the credential was added
5. Review `AuditLogs` for the actor's other activity in the same session

## References

- [Microsoft: Midnight Blizzard January 2024](https://www.microsoft.com/en-us/security/blog/2024/01/25/midnight-blizzard-guidance-for-responders-on-nation-state-attack/)
- [MITRE T1098.001](https://attack.mitre.org/techniques/T1098/001/)
- [MITRE T1528](https://attack.mitre.org/techniques/T1528/)
