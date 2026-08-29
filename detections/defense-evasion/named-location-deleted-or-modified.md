# Named Location Deleted or Modified

## Technique
**MITRE ATT&CK**: [T1562.001 - Impair Defenses: Disable or Modify Tools](https://attack.mitre.org/techniques/T1562/001/)  
**Tactic**: Defense Evasion

## What the attacker is doing

Named locations are IP range or country definitions that Conditional Access policies use as conditions. A CA policy that blocks sign-ins from outside trusted IP ranges is completely neutralized if the named location definition is modified to include the attacker's IP range - or deleted entirely.

This is a more subtle attack than disabling the CA policy directly because:
- The CA policy object itself remains enabled and visible in monitoring dashboards
- Alerts that monitor for CA policy state changes (`enabled` → `disabled`) will not fire
- The named location change may be attributed to routine network maintenance if not investigated
- The attacker gains persistent sign-in access without triggering IP-based blocks

An attacker with Conditional Access Administrator or Global Administrator privileges can make this change in seconds through the Entra ID portal or via the Microsoft Graph API.

## Detection

### KQL (Microsoft Sentinel)

```kql
let starttime = todatetime('{{StartTimeISO}}');
let endtime   = todatetime('{{EndTimeISO}}');
AuditLogs
| where TimeGenerated between (starttime .. endtime)
| where Category =~ "Policy"
| where OperationName in~ ("Add named location", "Update named location", "Delete named location")
| where Result =~ "success"
| extend LocationName = tostring(TargetResources[0].displayName)
| extend ActorUpn     = tostring(parse_json(tostring(InitiatedBy.user)).userPrincipalName)
| extend ActorApp     = tostring(parse_json(tostring(InitiatedBy.app)).displayName)
| extend ActorIp      = iff(
      isnotempty(tostring(parse_json(tostring(InitiatedBy.user)).ipAddress)),
      tostring(parse_json(tostring(InitiatedBy.user)).ipAddress),
      tostring(parse_json(tostring(InitiatedBy.app)).ipAddress))
| extend Actor = iff(isnotempty(ActorUpn), ActorUpn, ActorApp)
| project TimeGenerated, OperationName, LocationName, Actor, ActorIp, CorrelationId
| sort by TimeGenerated desc
```

### SIGMA

```yaml
title: Entra ID Named Location Deleted or Modified
id: d3bd4d0b-fc19-4fd8-a42a-a1b40406a8ae
related:
    - id: 50a3c7aa-ec29-44a4-92c1-fce229eef6fc
      type: similar
    - id: 26e7c5e2-6545-481e-b7e6-050143459635
      type: similar
status: test
tags:
    - attack.defense-evasion
    - attack.t1562.001
detection:
    selection:
        Category: Policy
        OperationName:
            - 'Delete named location'
            - 'Update named location'
    condition: selection
level: medium
```

**Contributed**: [Azure-Sentinel#14240](https://github.com/Azure/Azure-Sentinel/pull/14240) (merged)

**Validation, 2026-08-23.** Ran the operation live in a real Entra ID tenant (Microsoft Entra ID P2 trial) to
confirm the shape instead of writing from documentation alone: created, updated and deleted a named IP-range
location. All three operations logged as `Category: Policy`, actor and app correctly attributed, and the
`TargetResources.modifiedProperties` shape for `NamedLocation` matches this detection's assumptions
(`displayName`, `ipRanges`, `isTrusted`, old/new value diff on update). Confirmed no equivalent rule exists in
elastic/detection-rules -- the only Conditional Access rule there only fires on `Update conditional access
policy`, never on a named location change.

**Contributed: elastic/detection-rules#6691** (opened 2026-08-24, superseding the earlier hold-and-wait
decision from 2026-08-20 -- David chose to open it rather than wait for the other 4 PRs to get reviewed
first).

## False Positives

- Authorized IP range updates to reflect legitimate network changes (office relocation, ISP change)
- Consolidation or renaming of named location objects

**Analyst note**: Compare the modification against your network change management records. If the change added a broad IP range (e.g., /8 or /16 from a cloud hosting provider) rather than a specific corporate IP, treat as an IOC. Cross-reference with sign-in logs from IPs now covered by the modified range.

## Investigation Steps

1. Identify what changed in the named location (old vs. new IP ranges)
2. Check sign-in logs for activity from newly included IP ranges in the 24h after the change
3. Verify the actor had an authorized reason for the change
4. If unauthorized: restore the original named location definition, review CA policy effectiveness

## References

- [Microsoft: Named locations in Conditional Access](https://learn.microsoft.com/en-us/entra/identity/conditional-access/location-condition)
- [MITRE T1562.001](https://attack.mitre.org/techniques/T1562/001/)
