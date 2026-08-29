# Conditional Access Policy Exclusion Added

## Technique
**MITRE ATT&CK**: [T1556.009 - Modify Authentication Process: Conditional Access](https://attack.mitre.org/techniques/T1556/009/)
**Tactic**: Defense Evasion

## What the attacker is doing

An attacker with Conditional Access Administrator or Global Administrator access narrows a policy's scope by adding their own account, a compromised guest account, or a service principal to its exclusion list. This achieves the same practical bypass as disabling the policy, without the state change (`enabled` → `disabled`) that most defenses monitor for, and without interrupting enforcement for every other user in the tenant.

MITRE documents this exact pattern under T1556.009: threat actors, including Scattered Spider, have added trusted locations and exclusions to Conditional Access policies in real intrusions to maintain access after initial compromise.

## Why standard detections miss it

Most Conditional Access monitoring watches for the policy's `State` property flipping between `enabled` and `disabled`. An exclusion added to an otherwise-enabled policy never touches that property, so it passes through that monitoring untouched. This detection intentionally excludes plain state transitions (covered by [Conditional Access policy disabled or deleted](conditional-access-policy-disabled.md)) and instead surfaces condition-level edits, so analysts review the raw old and new values for a growing exclude-users or exclude-groups list.

## Detection

### KQL (Microsoft Sentinel)

```kql
let timeframe = 14d;
AuditLogs
| where TimeGenerated >= ago(timeframe)
| where Category =~ "Policy"
| where OperationName =~ "Update conditional access policy"
| where Result =~ "success"
| mv-expand ModProp = TargetResources[0].modifiedProperties
| extend PropName = tostring(ModProp.displayName)
| extend OldValue = tostring(ModProp.oldValue)
| extend NewValue = tostring(ModProp.newValue)
| where PropName !~ "State"
| where PropName has "Condition" or NewValue has "exclude" or OldValue has "exclude"
| extend PolicyName = tostring(TargetResources[0].displayName)
| extend PolicyId   = tostring(TargetResources[0].id)
| extend ActorUpn = tostring(InitiatedBy.user.userPrincipalName)
| extend ActorApp = tostring(InitiatedBy.app.displayName)
| extend Actor    = iff(isnotempty(ActorUpn), ActorUpn, ActorApp)
| extend ActorIp  = iff(
      isnotempty(tostring(InitiatedBy.user.ipAddress)),
      tostring(InitiatedBy.user.ipAddress),
      tostring(InitiatedBy.app.ipAddress))
| extend AccountName      = iff(ActorUpn has "@", tostring(split(ActorUpn, "@")[0]), Actor)
| extend AccountUPNSuffix = iff(ActorUpn has "@", tostring(split(ActorUpn, "@")[1]), "")
| project TimeGenerated, PolicyName, PolicyId, PropName, OldValue, NewValue, Actor, AccountName, AccountUPNSuffix, ActorIp, CorrelationId
| sort by TimeGenerated desc
```

### SIGMA

```yaml
title: Entra ID Conditional Access Policy Exclusion Added
id: 6b9a4e2a-1b3f-4c8e-9d0e-2f7c5a8b3e11
status: test
tags:
    - attack.defense-evasion
    - attack.t1556.009
detection:
    selection:
        Category: Policy
        OperationName: 'Update conditional access policy'
    filter:
        ModifiedProperty|contains: 'State'
    condition: selection and not filter
level: medium
```

**Contributed**: [Azure-Sentinel#14789](https://github.com/Azure/Azure-Sentinel/pull/14789)

## False Positives

- Legitimate policy tuning that narrows scope for a documented, valid reason
- Break-glass account exclusions added and recorded in change management
- Scheduled policy reviews that adjust exclusion lists as roles change

**Analyst note**: The signal is highest when the excluded identity is privileged, recently created, or not a known break-glass account. Every result must be validated against change records before escalating; this is intentionally a high-recall, analyst-reviewed query rather than a fire-and-forget alert.

## Investigation Steps

1. Identify the policy, the exact property changed, and the old vs. new value
2. Identify the excluded identity and check whether it is privileged, recently created, or a known break-glass account
3. Check for a corresponding change record or ticket
4. If unauthorized: remove the exclusion, review the actor's other recent Conditional Access changes, and audit sign-ins from the excluded identity during the exclusion window

## References

- [Microsoft: Conditional Access overview](https://learn.microsoft.com/entra/identity/conditional-access/overview)
- [Microsoft: Audit activity reference](https://learn.microsoft.com/entra/identity/monitoring-health/reference-audit-activities)
- [MITRE T1556.009](https://attack.mitre.org/techniques/T1556/009/)
