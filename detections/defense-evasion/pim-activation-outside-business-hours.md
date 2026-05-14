# PIM Role Activation Outside Business Hours

## Technique
**MITRE ATT&CK**: [T1078.004 — Valid Accounts: Cloud Accounts](https://attack.mitre.org/techniques/T1078/004/)  
**Tactic**: Persistence, Privilege Escalation

## What the attacker is doing

Privileged Identity Management (PIM) provides just-in-time privileged access — a user activates an eligible role for a limited time window rather than holding it permanently. An attacker who compromises a PIM-eligible account can activate the role if the activation policy does not require MFA or manager approval.

Attackers deliberately choose off-hours windows for PIM activation because:
- Security operations teams are understaffed or absent outside business hours
- Automated alerts may not be triaged until the following morning
- The activation window (typically 1-8 hours) provides sufficient time to complete the attack before detection
- Off-hours activity is less likely to be noticed by the legitimate account holder

This detection flags activations outside 07:00-20:00 UTC on weekdays and any activation on weekends. Adjust the time window to your organization's actual business hours.

## Detection

### KQL (Microsoft Sentinel)

```kql
let starttime = todatetime('{{StartTimeISO}}');
let endtime   = todatetime('{{EndTimeISO}}');
let BusinessHourStart = 7;
let BusinessHourEnd   = 20;
AuditLogs
| where TimeGenerated between (starttime .. endtime)
| where Category =~ "RoleManagement"
| where OperationName in~ (
      "Add member to role (PIM activation)",
      "Add member to role. (PIM activation)",
      "Add eligible member to role. (PIM activation)"
  )
| where Result =~ "success"
| extend ActivatingUserUpn = tostring(TargetResources[0].userPrincipalName)
| extend RoleName = iff(
      isnotempty(tostring(TargetResources[1].displayName)),
      tostring(TargetResources[1].displayName),
      tostring(TargetResources[0].displayName))
| extend ActorUpn = tostring(parse_json(tostring(InitiatedBy.user)).userPrincipalName)
| extend ActorIp  = iff(
      isnotempty(tostring(parse_json(tostring(InitiatedBy.user)).ipAddress)),
      tostring(parse_json(tostring(InitiatedBy.user)).ipAddress),
      tostring(parse_json(tostring(InitiatedBy.app)).ipAddress))
| extend HourOfDay    = hourofday(TimeGenerated)
| extend DayOfWeekNum = toint(dayofweek(TimeGenerated) / 1d)
| extend IsWeekend              = DayOfWeekNum == 0 or DayOfWeekNum == 6
| extend IsOutsideBusinessHours = HourOfDay < BusinessHourStart or HourOfDay >= BusinessHourEnd
| where IsWeekend or IsOutsideBusinessHours
| project TimeGenerated, RoleName, ActivatingUserUpn, ActorIp, HourOfDay, DayOfWeekNum, IsWeekend, IsOutsideBusinessHours, CorrelationId
| sort by TimeGenerated desc
```

**Contributed**: [Azure-Sentinel#14240](https://github.com/Azure/Azure-Sentinel/pull/14240)

## False Positives

- On-call administrators handling after-hours incidents
- Authorized Global Administrators working across time zones
- Automated runbooks activating PIM roles via service principals

**Analyst note**: This is a high-value hunting query, not a high-fidelity alert. Run it during threat hunting cycles or as a weekly review. For every result, check whether there is an on-call ticket, incident, or change request that explains the activation. An activation with no corresponding ticket during a weekend night is a strong IOC.

## Investigation Steps

1. Check whether the activating user had an on-call assignment or active incident ticket at the time
2. Review the IP address — does it match the user's typical location?
3. Check what the user did with the activated role during the activation window
4. For service principal activations (no ActorUpn), verify the runbook or automation that triggered it

## References

- [Microsoft: PIM role activation](https://learn.microsoft.com/en-us/entra/id-governance/privileged-identity-management/pim-how-to-activate-role)
- [MITRE T1078.004](https://attack.mitre.org/techniques/T1078/004/)
