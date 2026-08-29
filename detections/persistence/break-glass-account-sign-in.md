# Break-Glass Account Sign-In Detected

## Technique
**MITRE ATT&CK**: [T1078.004 - Valid Accounts: Cloud Accounts](https://attack.mitre.org/techniques/T1078/004/)
**Tactic**: Initial Access, Persistence

## What the attacker is doing

Break-glass (emergency access) accounts are cloud-only, highly privileged accounts that organizations deliberately exclude from Conditional Access policies and day-to-day MFA enforcement so they remain usable if every other authentication path fails. Because of that exclusion, a successful sign-in to one of these accounts bypasses the same controls that protect every other identity in the tenant.

An attacker who identifies and compromises a break-glass account (through misconfigured exclusion lists, insider knowledge, or credential exposure) gets a foothold that is, by design, immune to the tenant's normal defenses. Microsoft's own guidance is that sign-in and credential-change activity on these accounts should be monitored continuously, not just tested quarterly.

## Why standard detections miss it

Generic sign-in monitoring treats break-glass accounts like any other account, and since they are used so rarely, a single sign-in rarely stands out in volume-based anomaly detection. There is also no way to infer which accounts are break-glass accounts from sign-in data alone; this detection depends on a maintained watchlist populated from the tenant's documented emergency-access inventory.

## Detection

### KQL (Microsoft Sentinel)

```kql
let starttime = todatetime('{{StartTimeISO}}');
let endtime = todatetime('{{EndTimeISO}}');
let BreakGlassAccounts = (
    _GetWatchlist('BreakGlassAccounts')
    | project AccountUPN = tolower(tostring(SearchKey))
);
SigninLogs
| where TimeGenerated between (starttime .. endtime)
| where tolower(UserPrincipalName) in (BreakGlassAccounts)
| extend City = tostring(LocationDetails.city)
| extend Country = tostring(LocationDetails.countryOrRegion)
| extend AccountName      = tostring(split(UserPrincipalName, "@")[0])
| extend AccountUPNSuffix = tostring(split(UserPrincipalName, "@")[1])
| project
    TimeGenerated, UserPrincipalName, AccountName, AccountUPNSuffix, UserId,
    IPAddress, City, Country, AppDisplayName, ResourceDisplayName, ResultType,
    ResultDescription, ConditionalAccessStatus, AuthenticationRequirement, CorrelationId
| sort by TimeGenerated desc
```

This query depends on a watchlist named `BreakGlassAccounts` whose `SearchKey` column holds the user principal names of the tenant's designated emergency access accounts. Populate it once from the tenant's documented break-glass account inventory. There is no vendor-neutral SIGMA equivalent for this detection: the watchlist join is a Sentinel-specific mechanism, and a SIGMA selection cannot express "any of these tenant-specific accounts" without hardcoding UPNs that would not be portable to another tenant.

**Contributed**: [Azure-Sentinel#14948](https://github.com/Azure/Azure-Sentinel/pull/14948)

## False Positives

- The organization's scheduled quarterly (or otherwise documented) break-glass access test
- A genuine tenant-wide lockout where the break-glass account is used as designed

**Analyst note**: Any match should be validated against the change calendar for a planned access-recovery test. Sign-ins that fall outside a documented test window, that originate from an unexpected IP address or country, or that are closely followed by a credential change or a privilege change on the same account (see [Break-glass account credentials or MFA modified](break-glass-account-credentials-modified.md) and [Break-glass account role or group membership changed](break-glass-account-role-or-group-membership-changed.md)) warrant immediate escalation.

## Investigation Steps

1. Check the change calendar for a documented, in-progress break-glass test
2. If no test is scheduled, treat as a confirmed incident and begin containment immediately
3. Review the sign-in's IP, country, device, and application against the account's expected usage pattern
4. Check the two companion break-glass queries for concurrent credential or role/group changes on the same account
5. If unauthorized: disable the account, rotate its credentials, and review who had knowledge of or access to it

## References

- [Microsoft: Manage emergency access accounts](https://learn.microsoft.com/entra/identity/role-based-access-control/security-emergency-access)
- [MITRE T1078.004](https://attack.mitre.org/techniques/T1078/004/)
