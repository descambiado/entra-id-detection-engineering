# Break-Glass Account Credentials or MFA Modified

## Technique
**MITRE ATT&CK**: [T1098 - Account Manipulation](https://attack.mitre.org/techniques/T1098/) / [T1556.006 - Modify Authentication Process: Multi-Factor Authentication](https://attack.mitre.org/techniques/T1556/006/)
**Tactic**: Persistence, Defense Evasion

## What the attacker is doing

Break-glass (emergency access) accounts exist to remain usable when every other authentication path in the tenant has failed, which only works if their credentials and registered security info stay exactly as documented between the periodic tests organizations run to validate them.

A password reset or a change to registered MFA methods outside a documented test window is a strong signal that either the account is being repurposed by an attacker for persistence, or that its emergency-access properties have silently drifted out of the state the runbook expects.

## Why standard detections miss it

Password reset and security-info-change monitoring generally applies the same thresholds and baselines to every account in the tenant. Break-glass accounts need the opposite treatment: because they should see effectively zero activity between tests, any single match is significant, which a generic anomaly threshold tuned for normal user accounts will not surface.

## Detection

### KQL (Microsoft Sentinel)

```kql
let starttime = todatetime('{{StartTimeISO}}');
let endtime = todatetime('{{EndTimeISO}}');
let BreakGlassAccounts = (
    _GetWatchlist('BreakGlassAccounts')
    | project AccountUPN = tolower(tostring(SearchKey))
);
let SecurityInfoOps = dynamic([
    "Admin registered security info",
    "Admin updated security info",
    "Admin deleted security info",
    "User registered security info",
    "User changed default security info",
    "User deleted security info",
    "User registered all required security info",
    "User started security info registration"
]);
let PasswordWords = dynamic(["password", "credential", "credentials"]);
let ChangeActionWords = dynamic(["change", "changed", "reset"]);
AuditLogs
| where TimeGenerated between (starttime .. endtime)
| where Result =~ "success"
| where OperationName in~ (SecurityInfoOps)
      or (OperationName has_any (PasswordWords) and OperationName has_any (ChangeActionWords))
| mv-apply TargetResource = TargetResources on (
      where TargetResource.type =~ "User"
      | extend TargetUpn = tolower(tostring(TargetResource.userPrincipalName))
  )
| where TargetUpn in (BreakGlassAccounts)
| extend ActorUpn = tostring(InitiatedBy.user.userPrincipalName)
| extend ActorApp = tostring(InitiatedBy.app.displayName)
| extend Actor    = iff(isnotempty(ActorUpn), ActorUpn, ActorApp)
| extend ActorIp  = iff(
      isnotempty(tostring(InitiatedBy.user.ipAddress)),
      tostring(InitiatedBy.user.ipAddress),
      tostring(InitiatedBy.app.ipAddress))
| extend AccountName      = tostring(split(TargetUpn, "@")[0])
| extend AccountUPNSuffix = tostring(split(TargetUpn, "@")[1])
| project
    TimeGenerated, OperationName, TargetUpn, AccountName, AccountUPNSuffix,
    Actor, ActorIp, CorrelationId
| sort by TimeGenerated desc
```

Password reset/change operation names are not consistent across tenants and Entra ID service versions, so credential resets are matched the same way the official "Multiple Password Reset by user" analytic rule does it: any `OperationName` that mentions a password/credential noun together with a change/reset verb, admin or self-service alike, rather than an exact-string list that silently misses variants. This query, like the other two in this pack, depends on a watchlist named `BreakGlassAccounts` whose `SearchKey` column holds the user principal names of the tenant's designated emergency access accounts; there is no vendor-neutral SIGMA equivalent for the same reason as the sign-in query in this pack.

**Contributed**: [Azure-Sentinel#14948](https://github.com/Azure/Azure-Sentinel/pull/14948)

## False Positives

- The organization's scheduled break-glass access test, which typically includes a credential rotation step
- A documented emergency-access review that intentionally re-registers MFA methods

**Analyst note**: Every match should be checked against the change calendar for a planned access-recovery test before escalating. A match with no corresponding test window, or one closely followed by a sign-in or a role and group membership change on the same account (see [Break-glass account sign-in detected](break-glass-account-sign-in.md) and [Break-glass account role or group membership changed](break-glass-account-role-or-group-membership-changed.md)), should be treated as high priority.

## Investigation Steps

1. Check the change calendar for a documented, in-progress break-glass test
2. Identify the actor who made the change and confirm they are authorized to manage the account
3. Check the two companion break-glass queries for a concurrent sign-in or role/group change
4. If unauthorized: revert the credential/MFA change if possible, rotate the account's credentials, and review who had access to make the change

## References

- [Microsoft: Manage emergency access accounts](https://learn.microsoft.com/entra/identity/role-based-access-control/security-emergency-access)
- [MITRE T1098](https://attack.mitre.org/techniques/T1098/)
- [MITRE T1556.006](https://attack.mitre.org/techniques/T1556/006/)
