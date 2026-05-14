# Conditional Access Policy Disabled or Deleted

## Technique
**MITRE ATT&CK**: [T1562.001 — Impair Defenses: Disable or Modify Tools](https://attack.mitre.org/techniques/T1562/001/)  
**Tactic**: Defense Evasion

## What the attacker is doing

Conditional Access policies are the primary enforcement layer in Entra ID — they define when MFA is required, which devices are trusted, and which locations are allowed. An attacker with Conditional Access Administrator or Global Administrator access can disable or delete a CA policy to remove enforcement for subsequent sign-ins.

**Disabling vs. deleting:**
- **Disabling** (`state: disabled`) is preferred by sophisticated attackers because it is reversible — the attacker can re-enable the policy before defenders notice, making the window of exposure harder to detect forensically
- **Deleting** is more destructive and irreversible, but leaves a clean audit trail with no policy object remaining

Common CA policies targeted:
- MFA requirement for all users or all admins
- Block legacy authentication (disabling this re-enables basic auth credential spraying)
- Require compliant or Hybrid Azure AD joined device
- Block sign-in from high-risk locations or countries

## Detection

### KQL (Microsoft Sentinel)

```kql
let starttime = todatetime('{{StartTimeISO}}');
let endtime   = todatetime('{{EndTimeISO}}');
let PolicyDeletions =
    AuditLogs
    | where TimeGenerated between (starttime .. endtime)
    | where OperationName =~ "Delete conditional access policy"
    | where Result =~ "success"
    | extend PolicyName = tostring(TargetResources[0].displayName)
    | extend ActorUpn   = tostring(parse_json(tostring(InitiatedBy.user)).userPrincipalName)
    | extend ActorApp   = tostring(parse_json(tostring(InitiatedBy.app)).displayName)
    | extend ActorIp    = iff(
          isnotempty(tostring(parse_json(tostring(InitiatedBy.user)).ipAddress)),
          tostring(parse_json(tostring(InitiatedBy.user)).ipAddress),
          tostring(parse_json(tostring(InitiatedBy.app)).ipAddress))
    | extend Actor      = iff(isnotempty(ActorUpn), ActorUpn, ActorApp)
    | extend ChangeType = "Deleted"
    | project TimeGenerated, ChangeType, PolicyName, Actor, ActorIp, CorrelationId;
let PolicyDisablements =
    AuditLogs
    | where TimeGenerated between (starttime .. endtime)
    | where OperationName =~ "Update conditional access policy"
    | where Result =~ "success"
    | mv-expand ModProp = TargetResources[0].modifiedProperties
    | where tostring(ModProp.displayName) =~ "State"
    | where tostring(ModProp.newValue) has "disabled"
    | extend PolicyName = tostring(TargetResources[0].displayName)
    | extend ActorUpn   = tostring(parse_json(tostring(InitiatedBy.user)).userPrincipalName)
    | extend ActorApp   = tostring(parse_json(tostring(InitiatedBy.app)).displayName)
    | extend ActorIp    = iff(
          isnotempty(tostring(parse_json(tostring(InitiatedBy.user)).ipAddress)),
          tostring(parse_json(tostring(InitiatedBy.user)).ipAddress),
          tostring(parse_json(tostring(InitiatedBy.app)).ipAddress))
    | extend Actor      = iff(isnotempty(ActorUpn), ActorUpn, ActorApp)
    | extend ChangeType = "Disabled"
    | project TimeGenerated, ChangeType, PolicyName, Actor, ActorIp, CorrelationId;
union PolicyDeletions, PolicyDisablements
| extend AccountName      = iff(Actor has "@", tostring(split(Actor, "@")[0]), Actor)
| extend AccountUPNSuffix = iff(Actor has "@", tostring(split(Actor, "@")[1]), "")
| sort by TimeGenerated desc
```

**Contributed**: [Azure-Sentinel#14240](https://github.com/Azure/Azure-Sentinel/pull/14240)

## False Positives

- Authorized policy cleanup during CA policy restructuring
- Testing or staging environments where policies are frequently toggled
- Policy migration workflows

**Analyst note**: Deletions are always higher priority than disablements. For disablements, check whether the policy was re-enabled within minutes — this could indicate an attacker testing the disable/re-enable cycle to understand detection coverage. Any CA policy change affecting MFA requirements for admins or blocking legacy authentication should be treated as critical until verified.

## Investigation Steps

1. Identify the actor and verify authorization through change management records
2. Review sign-in logs in the 24h after the policy change — did any previously blocked sign-ins now succeed?
3. Check whether other CA policies were modified by the same actor in the same session
4. If unauthorized: immediately re-enable or recreate the policy, then investigate how the actor's privileges were obtained

## References

- [Microsoft: Conditional Access overview](https://learn.microsoft.com/en-us/entra/identity/conditional-access/overview)
- [MITRE T1562.001](https://attack.mitre.org/techniques/T1562/001/)
