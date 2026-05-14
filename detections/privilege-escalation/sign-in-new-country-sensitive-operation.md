# Sign-In from New Country Followed by Sensitive Operation

## Technique
**MITRE ATT&CK**: [T1078.004 — Valid Accounts: Cloud Accounts](https://attack.mitre.org/techniques/T1078/004/) · [T1098 — Account Manipulation](https://attack.mitre.org/techniques/T1098/)  
**Tactic**: Initial Access, Persistence, Privilege Escalation

## What the attacker is doing

An attacker using stolen credentials signs in from their own location — which is geographically novel for the victim account — and immediately performs a high-value administrative action. The combination of a new sign-in origin and an immediate sensitive operation is a strong post-compromise signal.

The key insight: attackers do not waste time after gaining access. They operate under time pressure because:
- The victim may detect the compromise and revoke sessions at any moment
- SOC teams work business hours — off-hours intrusions have more runway but on-hours attackers compensate with speed
- The first privileged action (adding persistence, escalating privilege, exfiltrating credentials) happens within minutes of the initial sign-in in most documented intrusions

This detection builds a 30-day country baseline per user from successful interactive sign-ins and correlates any novel-country sign-in with a sensitive AuditLogs operation within one hour by the same user.

**Sensitive operations monitored:**
- `Add member to role.` — direct privilege escalation
- `Consent to application` — OAuth persistence
- `Add service principal credentials` — app credential backdoor
- `Update application - Certificates and secrets management` — app credential rotation
- `Add application` — new app registration
- `Delete/Update conditional access policy` — defense weakening
- `Set domain authentication` — Golden SAML setup
- `Add member to role (PIM activation)` — PIM-based privilege escalation

## Why standard detections miss it

Individual signals — a new-country sign-in, or a role assignment — each generate noise on their own. The correlation of both events within a narrow time window for the same user dramatically reduces false positives. An administrator traveling and doing routine work will have both events, but the travel will likely be known and the operations unremarkable. An attacker will trigger both events in rapid succession for the same account.

## Detection

### KQL (Microsoft Sentinel)

```kql
let starttime = todatetime('{{StartTimeISO}}');
let endtime = todatetime('{{EndTimeISO}}');
let lookback = starttime - 30d;
let correlationWindow = 1h;
let sensitiveOps = dynamic([
    "Add member to role.",
    "Consent to application",
    "Add service principal credentials",
    "Update application - Certificates and secrets management",
    "Add application",
    "Delete conditional access policy",
    "Update conditional access policy",
    "Set domain authentication",
    "Add member to role (PIM activation)"
]);
let BaselineCountries =
    SigninLogs
    | where TimeGenerated between (lookback .. starttime)
    | where ResultType == 0
    | where isnotempty(Location)
    | extend UserUpn = tolower(UserPrincipalName)
    | summarize KnownCountries = make_set(Location) by UserUpn;
let NewCountrySignIns =
    SigninLogs
    | where TimeGenerated between (starttime .. endtime)
    | where ResultType == 0
    | where isnotempty(Location)
    | extend UserUpn = tolower(UserPrincipalName)
    | join kind=leftouter BaselineCountries on $left.UserUpn == $right.UserUpn
    | where isnull(KnownCountries) or not(set_has_element(KnownCountries, Location))
    | project SignInTime = TimeGenerated, UserUpn, SignInIP = IPAddress, NewCountry = Location, AppDisplayName;
AuditLogs
| where TimeGenerated between (starttime .. endtime)
| where OperationName has_any (sensitiveOps)
| where Result =~ "success"
| extend UserUpn    = tolower(tostring(parse_json(tostring(InitiatedBy.user)).userPrincipalName))
| extend AuditIp    = tostring(parse_json(tostring(InitiatedBy.user)).ipAddress)
| extend TargetName = tostring(TargetResources[0].displayName)
| where isnotempty(UserUpn)
| join kind=inner NewCountrySignIns on UserUpn
| where TimeGenerated between (SignInTime .. (SignInTime + correlationWindow))
| extend TimeDeltaMinutes = datetime_diff('minute', TimeGenerated, SignInTime)
| extend AccountName      = tostring(split(UserUpn, "@")[0])
| extend AccountUPNSuffix = tostring(split(UserUpn, "@")[1])
| project SignInTime, OperationTime = TimeGenerated, TimeDeltaMinutes, UserUpn,
    AccountName, AccountUPNSuffix, NewCountry, SignInIP, AuditIp, OperationName, TargetName, AppDisplayName
| sort by SignInTime desc
```

**Contributed**: [Azure-Sentinel#14262](https://github.com/Azure/Azure-Sentinel/pull/14262)

## False Positives

- Administrators working while traveling
- Global teams with members in multiple countries performing routine administrative work
- VPN or proxy usage that changes the apparent country of sign-in

**Analyst note**: The `TimeDeltaMinutes` column is your key triage field. A delta under 5 minutes between sign-in and a privileged operation from a new country is a near-certain IOC. A delta of 45-60 minutes from a known travel destination with routine operations is likely benign.

## Investigation Steps

1. Check the `NewCountry` against any known travel records or VPN configurations
2. Review the `TimeDeltaMinutes` — faster = more suspicious
3. Verify whether the `OperationName` is routine for this user (e.g., a Global Admin who regularly assigns roles vs. a standard user who never does)
4. Check for additional sign-ins from the same IP in other user accounts — shared infrastructure indicates a targeted attack
5. If suspicious: revoke all sessions, force MFA re-registration, notify the user

## References

- [Microsoft: Sign-in logs reference](https://learn.microsoft.com/en-us/entra/identity/monitoring-health/reference-sign-ins-error-codes)
- [MITRE T1078.004](https://attack.mitre.org/techniques/T1078/004/)
