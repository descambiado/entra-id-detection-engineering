# Workload Identity Sign-In From New Country

## Technique
**MITRE ATT&CK**: [T1078.004 — Valid Accounts: Cloud Accounts](https://attack.mitre.org/techniques/T1078/004/)  
**Tactic**: Initial Access, Credential Access

## What the attacker is doing

Service principals (workload identities) authenticate using client credentials: a client secret or certificate tied to an application registration. Unlike human accounts, workload identities cannot use MFA and are not protected by Conditional Access location policies in most configurations.

When an attacker steals a client secret — from a leaked `.env` file, a misconfigured CI/CD secret store, a compromised developer machine, or a repository scan — they can authenticate as that SP from anywhere. The stolen credential looks identical to legitimate traffic in the sign-in log.

The geographic baseline is the signal: legitimate workload identities have predictable infrastructure. A GitHub Actions runner authenticating as an SP will always appear from GitHub's IP ranges in a consistent region. Azure DevOps pipelines sign in from Microsoft's datacenter IPs. An SP that has never signed in from Brazil suddenly authenticating from a Brazilian IP is not a false positive — it is a credential being replayed from wherever the attacker happens to be operating.

## Why standard detections miss it

`AADServicePrincipalSignInLogs` is underutilized in most detection stacks. Most organizations focus AuditLog and SigninLogs-based rules on human accounts. This query specifically targets the SP sign-in table with a per-identity geographic baseline, which requires joining two time windows rather than a static allowlist.

## Detection

### KQL (Microsoft Sentinel)

```kql
let timeframe = 1d;
let lookback = 30d;
let BaselineCountries =
    AADServicePrincipalSignInLogs
    | where TimeGenerated >= ago(timeframe + lookback) and TimeGenerated < ago(timeframe)
    | where ResultType == 0
    | where isnotempty(Location)
    | summarize KnownCountries = make_set(Location) by ServicePrincipalId;
AADServicePrincipalSignInLogs
| where TimeGenerated >= ago(timeframe)
| where ResultType == 0
| where isnotempty(Location)
| join kind=leftouter hint.strategy=broadcast BaselineCountries on ServicePrincipalId
| where isnull(KnownCountries) or not(set_has_element(KnownCountries, Location))
| extend AccountName = ServicePrincipalName
| project TimeGenerated, ServicePrincipalId, ServicePrincipalName, AccountName,
          AppId, Location, IPAddress, ResourceDisplayName, CorrelationId
| sort by TimeGenerated desc
```

**Contributed**: [Azure/Azure-Sentinel#14281](https://github.com/Azure/Azure-Sentinel/pull/14281)

## False Positives

- New workload identity with less than 30 days of sign-in history (no baseline exists yet)
- Legitimate infrastructure migration moving a pipeline from one cloud region or provider to another
- Global organizations with multi-region deployment where an SP is intentionally used from multiple geographies

**Analyst note**: Filter for SPs that have at least 30 days of baseline data (`KnownCountries` is not null). For SPs with an established baseline, the false positive rate is very low — the infrastructure footprint of a legitimate workload identity is almost never dynamic.

## Investigation Steps

1. Identify the SP: check `ServicePrincipalName` and `AppId` in Entra ID > App Registrations
2. Review who owns the application and when it was last modified
3. Check the signing key/secret history: recent credential additions are a strong indicator of compromise
4. Look at what resources the SP accessed in the anomalous session: `AADServicePrincipalSignInLogs | where ServicePrincipalId == "<id>" | where Location == "<new country>"`
5. Correlate with any AuditLog events (consent grants, role assignments, credential additions) from the same time window
6. If confirmed malicious: revoke all credentials on the SP, review all permissions, and audit what the SP accessed

## References

- [Microsoft: Secure workload identities](https://learn.microsoft.com/en-us/entra/workload-id/workload-identities-overview)
- [MITRE T1078.004](https://attack.mitre.org/techniques/T1078/004/)
