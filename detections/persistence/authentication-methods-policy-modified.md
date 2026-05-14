# Authentication Methods Policy Modified

## Technique
**MITRE ATT&CK**: [T1556.006 — Modify Authentication Process: Multi-Factor Authentication](https://attack.mitre.org/techniques/T1556/006/)  
**Tactic**: Defense Evasion, Persistence

## What the attacker is doing

The tenant-wide authentication methods policy controls which MFA methods are enabled or disabled for all users in the organization. An attacker with Global Administrator access can modify this policy to:

- **Disable strong methods** (FIDO2 security keys, certificate-based authentication) to force users onto weaker methods that the attacker can intercept or bypass
- **Enable SMS/voice call** if it was previously disabled — enabling SIM-swap attacks against any user in the tenant
- **Disable the Microsoft Authenticator app** to force password-only authentication in certain flows

This is a tenant-level attack with wide blast radius — it affects every user, not just the compromised account. It is distinct from:
- **Identity Protection MFA registration policy** (`Update User Risk and MFA Registration Policy`) — which controls whether risky users must re-register MFA
- **Per-user MFA settings** — which affect individual accounts

The audit event is `Update authentication methods policy` under Category `Policy`.

## Detection

### SIGMA

```yaml
title: Entra ID Authentication Methods Policy Modified
id: eaf4cd5a-f700-46ad-ace6-d8caede30ea7
status: test
tags:
    - attack.defense-evasion
    - attack.persistence
    - attack.t1556.006
detection:
    selection:
        Category: Policy
        OperationName: 'Update authentication methods policy'
    condition: selection
level: high
```

**Contributed**: [SigmaHQ/sigma#6012](https://github.com/SigmaHQ/sigma/pull/6012)

### KQL (Microsoft Sentinel)

```kql
let starttime = todatetime('{{StartTimeISO}}');
let endtime   = todatetime('{{EndTimeISO}}');
AuditLogs
| where TimeGenerated between (starttime .. endtime)
| where Category =~ "Policy"
| where OperationName =~ "Update authentication methods policy"
| where Result =~ "success"
| extend ActorUpn = tostring(parse_json(tostring(InitiatedBy.user)).userPrincipalName)
| extend ActorApp = tostring(parse_json(tostring(InitiatedBy.app)).displayName)
| extend ActorIp  = iff(
      isnotempty(tostring(parse_json(tostring(InitiatedBy.user)).ipAddress)),
      tostring(parse_json(tostring(InitiatedBy.user)).ipAddress),
      tostring(parse_json(tostring(InitiatedBy.app)).ipAddress))
| extend Actor = iff(isnotempty(ActorUpn), ActorUpn, ActorApp)
| mv-expand ModProp = TargetResources[0].modifiedProperties
| extend PropName = tostring(ModProp.displayName)
| extend OldValue = tostring(ModProp.oldValue)
| extend NewValue = tostring(ModProp.newValue)
| project TimeGenerated, PropName, OldValue, NewValue, Actor, ActorIp, CorrelationId
| sort by TimeGenerated desc
```

## False Positives

- Authorized changes as part of security hardening (e.g., disabling SMS in favour of FIDO2)
- Planned rollout or retirement of authentication methods by identity administrators
- Microsoft-initiated policy updates for deprecated methods

**Analyst note**: Changes that disable stronger methods (FIDO2, certificate-based auth) or enable weaker ones (SMS, voice) are higher risk. Changes that harden the policy (disable SMS, enforce FIDO2) are likely benign. Always verify against your identity team's change calendar.

## Investigation Steps

1. Identify which specific method was enabled or disabled (`PropName`, `OldValue`, `NewValue`)
2. Verify the change against your identity team's change management records
3. If SMS or voice was enabled: check immediately for SIM-swap activity against privileged accounts
4. If strong methods were disabled: assess the impact on users who were exclusively using those methods
5. If unauthorized: revert the policy and review the actor account for further compromise

## References

- [Microsoft: Authentication methods policy](https://learn.microsoft.com/en-us/entra/identity/authentication/concept-authentication-methods-manage)
- [MITRE T1556.006](https://attack.mitre.org/techniques/T1556/006/)
