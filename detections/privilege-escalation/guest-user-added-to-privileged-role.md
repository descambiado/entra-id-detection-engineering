# Guest User Added to Privileged Entra ID Role

## Technique
**MITRE ATT&CK**: [T1098.003 — Account Manipulation: Additional Cloud Credentials](https://attack.mitre.org/techniques/T1098/003/)  
**Tactic**: Persistence, Privilege Escalation

## What the attacker is doing

An attacker who has compromised a privileged internal account adds a guest identity they control (from an external tenant) to a high-privilege directory role such as Global Administrator, Privileged Role Administrator, or Security Administrator.

This is a cross-tenant persistence technique. The guest identity is anchored in the attacker's own tenant — meaning:
- When the victim remediates the compromised internal account, the attacker retains access through the guest
- Resetting passwords, revoking sessions, or disabling the internal account does not affect the guest
- The guest can be used to re-add the compromised account or add additional backdoors

Guest accounts are identified by the `#EXT#` string in their UPN (e.g., `attacker_gmail.com#EXT#@victim.onmicrosoft.com`). This detection fires specifically on that pattern combined with a direct role assignment — bypassing PIM (Privileged Identity Management) is an additional red flag.

## Why standard detections miss it

Existing SIGMA rules covering role assignments detect:
- PIM eligible member additions (`Add eligible member (permanent/eligible)`)
- Device admin role additions (by specific role GUIDs)

None specifically combine guest UPN detection with a direct `Add member to role.` assignment. An analyst reviewing generic role assignment alerts may not notice the `#EXT#` marker in a noisy environment.

## Detection

### KQL (Microsoft Sentinel)

```kql
let starttime = todatetime('{{StartTimeISO}}');
let endtime   = todatetime('{{EndTimeISO}}');
AuditLogs
| where TimeGenerated between (starttime .. endtime)
| where Category =~ "RoleManagement"
| where OperationName =~ "Add member to role."
| where Result =~ "success"
| mv-expand TargetResource = TargetResources
| where tostring(TargetResource.type) =~ "User"
| extend TargetUpn = tolower(tostring(TargetResource.userPrincipalName))
| where TargetUpn contains "#ext#"
| extend RoleName  = tostring(TargetResources[0].displayName)
| extend ActorUpn  = tolower(tostring(parse_json(tostring(InitiatedBy.user)).userPrincipalName))
| extend ActorIp   = iff(
      isnotempty(tostring(parse_json(tostring(InitiatedBy.user)).ipAddress)),
      tostring(parse_json(tostring(InitiatedBy.user)).ipAddress),
      tostring(parse_json(tostring(InitiatedBy.app)).ipAddress))
| extend AccountName      = tostring(split(TargetUpn, "@")[0])
| extend AccountUPNSuffix = tostring(split(TargetUpn, "@")[1])
| project TimeGenerated, TargetUpn, AccountName, AccountUPNSuffix, RoleName, ActorUpn, ActorIp, CorrelationId
| sort by TimeGenerated desc
```

### SIGMA

```yaml
title: Guest User Added to Privileged Entra ID Role
id: 1f52cd1a-34ee-4f32-852a-4aa3ed62e08b
status: test
tags:
    - attack.persistence
    - attack.privilege-escalation
    - attack.t1098.003
detection:
    selection:
        Category: RoleManagement
        OperationName: 'Add member to role.'
        TargetResources|contains: '#EXT#'
    condition: selection
level: high
```

**Contributed**: [SigmaHQ/sigma#6012](https://github.com/SigmaHQ/sigma/pull/6012)

## False Positives

- Deliberate cross-tenant collaboration where a guest is legitimately required to manage tenant resources
- Automated provisioning pipelines using guest identities as service accounts

**Analyst note**: Verify whether the guest identity's home tenant is a known partner. An `#EXT#` UPN from a personal domain (gmail.com, outlook.com, protonmail.com) added to a privileged role is a near-certain IOC with no legitimate operational justification in most enterprise environments.

## Investigation Steps

1. Identify the actor who performed the assignment (`ActorUpn`, `ActorIp`)
2. Check if the actor account itself is compromised: recent sign-ins from new countries, MFA changes
3. Check the guest account's home tenant — look up the external domain
4. Review what actions the guest has performed since being added to the role
5. Remove the guest from the role immediately if not authorized; review all role assignments made by the same actor

## References

- [Microsoft: Security operations for privileged accounts](https://learn.microsoft.com/en-us/entra/architecture/security-operations-privileged-accounts)
- [MITRE T1098.003](https://attack.mitre.org/techniques/T1098/003/)
