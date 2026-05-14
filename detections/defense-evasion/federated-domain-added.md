# Federated Domain Added to Tenant (Golden SAML Setup)

## Technique
**MITRE ATT&CK**: [T1484.002 — Domain Trust Modification: Trust Modification](https://attack.mitre.org/techniques/T1484/002/)  
**Tactic**: Defense Evasion, Persistence, Privilege Escalation

## What the attacker is doing

This is one of the most devastating persistence techniques in cloud identity environments. An attacker who has obtained Global Administrator access converts a managed domain to federated authentication by configuring a malicious Identity Provider (IdP) under their control.

After federation is established:
1. Entra ID no longer validates credentials for that domain internally — it delegates to the attacker's IdP
2. The attacker's IdP can issue a valid SAML token asserting **any user identity** in the tenant
3. The SAML assertion bypasses MFA because Entra ID trusts the assertion from the IdP
4. Access persists even after the compromised admin account is disabled, passwords are reset, or sessions are revoked — because the federation trust relationship remains active at the domain level

This technique was observed in the **SolarWinds/SUNBURST** intrusion (Midnight Blizzard / Cozy Bear) and was publicly described as the **Golden SAML** attack. It is a Tier-0 persistence technique — one of the most difficult to detect and remediate.

The audit event is `Set domain authentication` with the authentication type transitioning to `Federated`. This event should be treated as a critical incident requiring immediate response.

## Why standard detections miss it

The existing SIGMA rule `azure_federation_modified` covers `Set federation settings on domain` — a different, related operation. The specific transition to federated authentication via `Set domain authentication` is a distinct audit event that specifically signals a managed-to-federated conversion and is not covered.

## Detection

### KQL (Microsoft Sentinel)

```kql
let starttime = todatetime('{{StartTimeISO}}');
let endtime   = todatetime('{{EndTimeISO}}');
AuditLogs
| where TimeGenerated between (starttime .. endtime)
| where OperationName =~ "Set domain authentication"
| where Result =~ "success"
| extend DomainName = tostring(TargetResources[0].displayName)
| extend ActorUpn   = tostring(parse_json(tostring(InitiatedBy.user)).userPrincipalName)
| extend ActorApp   = tostring(parse_json(tostring(InitiatedBy.app)).displayName)
| extend ActorIp    = iff(
      isnotempty(tostring(parse_json(tostring(InitiatedBy.user)).ipAddress)),
      tostring(parse_json(tostring(InitiatedBy.user)).ipAddress),
      tostring(parse_json(tostring(InitiatedBy.app)).ipAddress))
| extend Actor = iff(isnotempty(ActorUpn), ActorUpn, ActorApp)
| mv-expand ModProp = TargetResources[0].modifiedProperties
| extend PropName = tostring(ModProp.displayName)
| extend OldValue = tostring(ModProp.oldValue)
| extend NewValue = tostring(ModProp.newValue)
| where NewValue has_any ("Federated", "federated")
| project TimeGenerated, DomainName, PropName, OldValue, NewValue, Actor, ActorIp, CorrelationId
| sort by TimeGenerated desc
```

**Contributed**: [Azure-Sentinel#14240](https://github.com/Azure/Azure-Sentinel/pull/14240)

## False Positives

- Authorized migration from cloud-only to hybrid identity (ADFS setup)
- Authorized third-party SSO integration (Okta, Ping, ADFS federation)
- Documented infrastructure changes approved through change management

**Analyst note**: Any result from this detection should be treated as **critical priority** until proven otherwise. Immediately verify with the Global Administrator who performed the action through an out-of-band channel (phone call, not email — the email account may be compromised). Check whether the IdP metadata URL points to a tenant/infrastructure owned by your organization.

## Investigation Steps

1. Identify the actor and verify through out-of-band communication
2. Check the federation metadata URL in the new IdP configuration — does it resolve to infrastructure you own?
3. Review all sign-ins authenticated via the federated domain since the change: `SigninLogs | where HomeTenantId != ResourceTenantId or AuthenticationProtocol =~ "saml20"`
4. Check for other Global Admin operations performed by the same actor in the 30 minutes before and after this event
5. If unauthorized: immediately revert domain to managed authentication, revoke all sessions for users in that domain, rotate all credentials

## References

- [Semperis: Golden SAML attack](https://www.semperis.com/blog/golden-saml-newly-discovered-attack-technique-forges-authentication-to-cloud-apps/)
- [Microsoft: How to detect federation changes](https://learn.microsoft.com/en-us/entra/identity/hybrid/how-to-connect-monitor-federation-changes)
- [MITRE T1484.002](https://attack.mitre.org/techniques/T1484/002/)
