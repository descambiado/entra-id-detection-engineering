# Entra ID Detection Engineering

Detection content for Microsoft Entra ID (Azure AD) threat scenarios - KQL hunting queries for Microsoft Sentinel and vendor-neutral SIGMA rules covering the full identity attack lifecycle.

Built by a SOC analyst who learned security from the attacker side first.

---

## Why this repo exists

Most detection content is written by people who read about attacks. This content is written by someone who understands how they actually work - the evasion logic, the timing, the operational security mistakes attackers make, and why standard detections miss them.

The focus is **Entra ID** because it is the single most targeted component in modern enterprise intrusions. Compromising identity in a cloud-first environment is equivalent to owning the network in an on-prem environment. Every detection here maps to a real technique observed in post-compromise activity from threat groups including Storm-0558, Midnight Blizzard, and AiTM phishing campaigns.

---

## MITRE ATT&CK Coverage

| Technique | Name | Detections |
|-----------|------|------------|
| T1528 | Steal Application Access Token | [OAuth consent to high-risk permission](detections/credential-access/oauth-consent-high-risk-permission.md) |
| T1556.006 | Modify Authentication Process: Multi-Factor Authentication | [MFA registration from unseen IP](detections/persistence/mfa-registration-from-unseen-ip.md), [Admin MFA registration for user](detections/persistence/admin-mfa-registration-for-user.md), [Authentication methods policy modified](detections/persistence/authentication-methods-policy-modified.md) |
| T1098 | Account Manipulation | [Cross-tenant access setting modified](detections/persistence/cross-tenant-access-setting-modified.md), [Sign-in from new country with sensitive operation](detections/privilege-escalation/sign-in-new-country-sensitive-operation.md) |
| T1098.003 | Account Manipulation: Additional Cloud Credentials | [Guest user added to privileged role](detections/privilege-escalation/guest-user-added-to-privileged-role.md), [Bulk role assignments in short window](detections/privilege-escalation/bulk-role-assignments.md) |
| T1078.004 | Valid Accounts: Cloud Accounts | [Sign-in from new country with sensitive operation](detections/privilege-escalation/sign-in-new-country-sensitive-operation.md), [PIM activation outside business hours](detections/defense-evasion/pim-activation-outside-business-hours.md) |
| T1562.001 | Impair Defenses: Disable or Modify Tools | [Named location deleted or modified](detections/defense-evasion/named-location-deleted-or-modified.md), [Conditional Access policy disabled or deleted](detections/defense-evasion/conditional-access-policy-disabled.md) |
| T1484.002 | Domain Trust Modification: Trust Modification | [Federated domain added to tenant](detections/defense-evasion/federated-domain-added.md) |

---

## Detection Index

### Credential Access

| Detection | Platform | Severity | PR |
|-----------|----------|----------|----|
| [OAuth consent to high-risk permission](detections/credential-access/oauth-consent-high-risk-permission.md) | Sentinel + SIGMA | High | [Azure-Sentinel](https://github.com/Azure/Azure-Sentinel/pull/14240), [SigmaHQ](https://github.com/SigmaHQ/sigma/pull/6012) |

### Persistence

| Detection | Platform | Severity | PR |
|-----------|----------|----------|----|
| [MFA registration from unseen IP](detections/persistence/mfa-registration-from-unseen-ip.md) | Sentinel | Medium | [Azure-Sentinel](https://github.com/Azure/Azure-Sentinel/pull/14262) |
| [Admin registered MFA method for another user](detections/persistence/admin-mfa-registration-for-user.md) | Sentinel + SIGMA | High | [Azure-Sentinel](https://github.com/Azure/Azure-Sentinel/pull/14262), [SigmaHQ](https://github.com/SigmaHQ/sigma/pull/6012) |
| [Authentication methods policy modified](detections/persistence/authentication-methods-policy-modified.md) | SIGMA | High | [SigmaHQ](https://github.com/SigmaHQ/sigma/pull/6012) |
| [Cross-tenant access setting modified](detections/persistence/cross-tenant-access-setting-modified.md) | SIGMA | High | [SigmaHQ](https://github.com/SigmaHQ/sigma/pull/6012) |

### Privilege Escalation

| Detection | Platform | Severity | PR |
|-----------|----------|----------|----|
| [Guest user added to privileged Entra ID role](detections/privilege-escalation/guest-user-added-to-privileged-role.md) | Sentinel + SIGMA | High | [Azure-Sentinel](https://github.com/Azure/Azure-Sentinel/pull/14240), [SigmaHQ](https://github.com/SigmaHQ/sigma/pull/6012) |
| [Bulk role assignments in short window](detections/privilege-escalation/bulk-role-assignments.md) | Sentinel | Medium | [Azure-Sentinel](https://github.com/Azure/Azure-Sentinel/pull/14262) |
| [Sign-in from new country with sensitive operation](detections/privilege-escalation/sign-in-new-country-sensitive-operation.md) | Sentinel | High | [Azure-Sentinel](https://github.com/Azure/Azure-Sentinel/pull/14262) |

### Defense Evasion

| Detection | Platform | Severity | PR |
|-----------|----------|----------|----|
| [Named location deleted or modified](detections/defense-evasion/named-location-deleted-or-modified.md) | Sentinel + SIGMA | Medium | [Azure-Sentinel](https://github.com/Azure/Azure-Sentinel/pull/14240), [SigmaHQ](https://github.com/SigmaHQ/sigma/pull/6012) |
| [Conditional Access policy disabled or deleted](detections/defense-evasion/conditional-access-policy-disabled.md) | Sentinel | High | [Azure-Sentinel](https://github.com/Azure/Azure-Sentinel/pull/14240) |
| [PIM role activation outside business hours](detections/defense-evasion/pim-activation-outside-business-hours.md) | Sentinel | Medium | [Azure-Sentinel](https://github.com/Azure/Azure-Sentinel/pull/14240) |
| [Federated domain added to tenant (Golden SAML)](detections/defense-evasion/federated-domain-added.md) | Sentinel | High | [Azure-Sentinel](https://github.com/Azure/Azure-Sentinel/pull/14240) |

---

## Methodology

Every detection in this repo follows the same process:

1. **Start from the attacker objective** - what does the attacker need to accomplish, and what is the minimum footprint to do it?
2. **Find the seam** - Entra ID always logs the action. The question is whether standard detections are looking at the right field, the right correlation window, or the right baseline.
3. **Build a baseline** - anomaly beats signature. A sign-in from a new country is noise. A sign-in from a new country *followed by a privileged operation within one hour* is signal.
4. **Validate the gap** - before writing, search the target repo for existing coverage. Every detection here was verified to fill a genuine gap.
5. **Reduce noise deliberately** - a detection that fires on everything is useless. Every query here has a specific threshold, correlation window, or filter that makes it actionable.

---

## Contributions

All content has been contributed upstream. The following PRs are merged or in review.

### Azure/Azure-Sentinel

| PR | Description | Status |
|----|-------------|--------|
| [#14173](https://github.com/Azure/Azure-Sentinel/pull/14173) | Entity-based incident triage guide | Merged May 4, 2026 |
| [#14207](https://github.com/Azure/Azure-Sentinel/pull/14207) | Short-window sign-in ASN mismatch detection | Merged May 7, 2026 |
| [#14208](https://github.com/Azure/Azure-Sentinel/pull/14208) | IP failure burst followed by successful sign-in | Merged May 7, 2026 |
| [#14213](https://github.com/Azure/Azure-Sentinel/pull/14213) | Service principal credential addition by rarely observed actor | Merged May 7, 2026 |
| [#14239](https://github.com/Azure/Azure-Sentinel/pull/14239) | Entra ID identity and application threat hunting pack (5 queries) | Merged May 13, 2026 |
| [#14240](https://github.com/Azure/Azure-Sentinel/pull/14240) | Defense weakening and privilege abuse hunting pack (3 queries) | In review |
| [#14262](https://github.com/Azure/Azure-Sentinel/pull/14262) | Cross-source correlation hunting pack (3 queries) | In review |

### SigmaHQ/sigma

| PR | Description | Status |
|----|-------------|--------|
| [#6012](https://github.com/SigmaHQ/sigma/pull/6012) | Azure Entra ID identity attack detections (6 rules) | In review |

---

## Open Source Contributions

All content in this repo has been contributed upstream to the community:

- **Microsoft Azure-Sentinel** - [github.com/Azure/Azure-Sentinel](https://github.com/Azure/Azure-Sentinel)
- **SigmaHQ** - [github.com/SigmaHQ/sigma](https://github.com/SigmaHQ/sigma)

---

## Author

**descambiado** - SOC Analyst L1 at Capgemini, targeting SIEM Engineer. Writing detections for Entra ID identity attacks contributed to Azure-Sentinel and SigmaHQ.

[github.com/descambiado](https://github.com/descambiado)
