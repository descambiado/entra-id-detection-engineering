# Cross-Tenant Access Setting Created or Modified

## Technique
**MITRE ATT&CK**: [T1098 — Account Manipulation](https://attack.mitre.org/techniques/T1098/)  
**Tactic**: Persistence

## What the attacker is doing

Entra ID Cross-Tenant Access Settings (XTAS) allow organizations to configure trust relationships with specific external tenants — defining which users from those tenants can access internal resources, whether their MFA and device compliance claims are trusted, and what inbound/outbound sync is permitted.

An attacker with Global Administrator access can add their own tenant as a trusted partner and configure inbound trust to accept MFA claims from that tenant. This creates a persistent access path that:
- Survives the remediation of all compromised internal accounts
- Bypasses MFA enforcement because the attacker's tenant is trusted for MFA
- Is invisible to CA policies that enforce MFA for guest users (if MFA trust is configured)
- Can enable cross-tenant synchronization, copying attacker-controlled identities into the victim tenant

This technique is increasingly relevant as more organizations use cross-tenant collaboration features for legitimate B2B workflows, providing cover for malicious configurations.

## Detection

### SIGMA

```yaml
title: Entra ID Cross-Tenant Access Setting Created or Modified
id: 9ae9b60b-014b-4b74-87eb-6c5fa3f304e0
status: test
tags:
    - attack.persistence
    - attack.t1098
detection:
    selection:
        OperationName:
            - 'Create a partner cross-tenant access setting'
            - 'Update a partner cross-tenant access setting'
            - 'Delete a partner cross-tenant access setting'
            - 'Update cross-tenant access settings'
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
| where OperationName in~ (
      "Create a partner cross-tenant access setting",
      "Update a partner cross-tenant access setting",
      "Delete a partner cross-tenant access setting",
      "Update cross-tenant access settings"
  )
| where Result =~ "success"
| extend PartnerTenant = tostring(TargetResources[0].displayName)
| extend ActorUpn = tostring(parse_json(tostring(InitiatedBy.user)).userPrincipalName)
| extend ActorApp = tostring(parse_json(tostring(InitiatedBy.app)).displayName)
| extend ActorIp  = iff(
      isnotempty(tostring(parse_json(tostring(InitiatedBy.user)).ipAddress)),
      tostring(parse_json(tostring(InitiatedBy.user)).ipAddress),
      tostring(parse_json(tostring(InitiatedBy.app)).ipAddress))
| extend Actor = iff(isnotempty(ActorUpn), ActorUpn, ActorApp)
| project TimeGenerated, OperationName, PartnerTenant, Actor, ActorIp, CorrelationId
| sort by TimeGenerated desc
```

## False Positives

- Authorized configuration of B2B direct connect for known partner organizations
- Planned cross-tenant synchronization setup for organizational mergers or acquisitions
- IT-approved partner onboarding performed by authorized administrators

**Analyst note**: Verify the partner tenant ID against your authorized partner list. An unknown tenant ID or a tenant registered in a free email provider domain (gmail.com, outlook.com) added as a trusted partner is an IOC. Pay particular attention to configurations that enable MFA trust from the partner tenant — this is the most dangerous setting.

## Investigation Steps

1. Identify the partner tenant ID from the audit event
2. Cross-reference against your approved partner list
3. Check if MFA trust or device compliance trust was enabled for the partner tenant
4. Review sign-ins from the partner tenant in the 24-48h after the configuration change
5. If unauthorized: remove the cross-tenant access setting and revoke any active cross-tenant sessions

## References

- [Microsoft: Cross-tenant access overview](https://learn.microsoft.com/en-us/entra/external-id/cross-tenant-access-overview)
- [MITRE T1098](https://attack.mitre.org/techniques/T1098/)
