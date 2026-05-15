# Service Principal Credential Addition by Non-Historical Actor

## Technique
**MITRE ATT&CK**: [T1098.001 — Additional Cloud Credentials](https://attack.mitre.org/techniques/T1098/001/)  
**Tactic**: Persistence

## What the attacker is doing

After establishing initial access in an Entra ID tenant — through a compromised admin account, a vulnerable application, or an over-permissioned service principal — an attacker adds a new password credential or X.509 certificate to an existing Service Principal. This gives them a stable long-term foothold that:

- Survives the victim user's password reset
- Is not tied to any human account subject to MFA or Conditional Access
- Operates as the SP's identity, inheriting whatever permissions the SP already holds
- Is difficult to spot because SP credentials are managed by application owners and change legitimately during key rotation cycles

This technique was used in Midnight Blizzard's 2023 Microsoft breach and is a documented persistence mechanism in Storm-0558 operations.

## Why standard detections miss it

The `Add service principal credentials` operation appears in AuditLogs regularly in any mature tenant — developers rotate secrets, CI/CD pipelines add deployment keys, automation accounts refresh certificates. Most SIEM rules alert on the operation unconditionally, generating enough noise that analysts suppress or tune it out.

The signal is not the operation itself but **who performed it**. In most tenants, the set of identities that legitimately manage SP credentials is small and stable: a handful of Application Administrators, DevOps service accounts, and the SP owners themselves. An actor outside that set performing this operation is anomalous.

This detection baselines the initiating identity over 90 days. DormantServicePrincipalUpdateCredsandLogsIn in the same repo baselines the SP object — both are useful, and both should be in your hunting queue.

## Detection

### KQL (Microsoft Sentinel)

```kql
let timeframe = 1d;
let lookback = 90d;
let KnownActorSet = toscalar(
    AuditLogs
    | where TimeGenerated >= ago(timeframe + lookback) and TimeGenerated < ago(timeframe)
    | where OperationName in~ (
          "Add service principal credentials",
          "Update application - Certificates and secrets management")
    | where Result =~ "success"
    | extend ActorUpn = tostring(InitiatedBy.user.userPrincipalName)
    | extend ActorApp = tostring(InitiatedBy.app.displayName)
    | extend Actor    = iff(isnotempty(ActorUpn), ActorUpn, ActorApp)
    | where isnotempty(Actor)
    | summarize make_set(Actor)
);
AuditLogs
| where TimeGenerated >= ago(timeframe)
| where OperationName in~ (
      "Add service principal credentials",
      "Update application - Certificates and secrets management")
| where Result =~ "success"
| extend ActorUpn   = tostring(InitiatedBy.user.userPrincipalName)
| extend ActorApp   = tostring(InitiatedBy.app.displayName)
| extend Actor      = iff(isnotempty(ActorUpn), ActorUpn, ActorApp)
| extend ActorIp    = iff(
      isnotempty(tostring(InitiatedBy.user.ipAddress)),
      tostring(InitiatedBy.user.ipAddress),
      tostring(InitiatedBy.app.ipAddress))
| extend TargetSpId   = tostring(TargetResources[0].id)
| extend TargetSpName = tostring(TargetResources[0].displayName)
| extend CredType = iff(
      TargetResources[0].modifiedProperties has "KeyCredentials",
      "Certificate", "Password")
| where not(set_has_element(KnownActorSet, Actor))
| extend AccountName      = iff(Actor has "@", tostring(split(Actor, "@")[0]), Actor)
| extend AccountUPNSuffix = iff(Actor has "@", tostring(split(Actor, "@")[1]), "")
| project TimeGenerated, Actor, AccountName, AccountUPNSuffix, ActorIp,
          TargetSpName, TargetSpId, CredType, OperationName, CorrelationId
| sort by TimeGenerated desc
```

**Contributed**: [Azure/Azure-Sentinel#14276](https://github.com/Azure/Azure-Sentinel/pull/14276)

## False Positives

- New Application Administrators or DevOps engineers who have never performed this action in the tenant before
- Infrastructure migrations where a new automation account takes over SP management
- Legitimate key rotation by a vendor or MSP that rotates on an infrequent schedule (less often than the 90-day lookback window)

**Analyst note**: Check the actor's role assignments in Entra ID and when those roles were assigned. An actor who was granted Application Administrator within the last 24 hours and immediately added credentials to a high-privilege SP is a strong IOC. Also check the target SP's permissions — SPs with Directory.ReadWrite.All, RoleManagement.ReadWrite.Directory, or access to production infrastructure are the highest-value targets.

## Investigation Steps

1. Identify the SP that received new credentials: `AuditLogs | where OperationName =~ "Add service principal credentials" | extend SpId = TargetResources[0].id`
2. Review what permissions the SP holds: check App Roles and OAuth2PermissionGrants in Entra ID
3. Determine when the actor was granted admin roles and whether the timing correlates with the credential addition
4. Check for sign-ins using the SP's new credentials in `AADServicePrincipalSignInLogs` within hours of the addition
5. If the SP is cloud-only and the credential was a password (not a cert), treat with high suspicion — legitimate CI/CD pipelines overwhelmingly prefer certificates or Managed Identities

## References

- [Microsoft: Midnight Blizzard guidance after the January 2024 breach](https://www.microsoft.com/en-us/security/blog/2024/01/25/midnight-blizzard-guidance-for-responders-on-nation-state-attack/)
- [MITRE T1098.001](https://attack.mitre.org/techniques/T1098/001/)
