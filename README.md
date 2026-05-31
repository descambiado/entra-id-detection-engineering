# Entra ID Detection Engineering

![GitHub Repo stars](https://img.shields.io/github/stars/descambiado/entra-id-detection-engineering?style=flat&color=blue)
![GitHub last commit](https://img.shields.io/github/last-commit/descambiado/entra-id-detection-engineering?style=flat)
![Azure-Sentinel PRs merged](https://img.shields.io/badge/Azure--Sentinel%20PRs%20merged-17-brightgreen?style=flat)
![Detections](https://img.shields.io/badge/detections-26-orange?style=flat)
![MITRE techniques](https://img.shields.io/badge/MITRE%20techniques-11-red?style=flat)

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
| T1528 | Steal Application Access Token | [OAuth consent to high-risk permission](detections/credential-access/oauth-consent-high-risk-permission.md), [High-privilege app role assigned to SP](detections/persistence/application-app-role-assigned-high-privilege.md), [SP credential addition followed by immediate sign-in](detections/credential-access/service-principal-credential-then-signin.md), [OAuth application redirect URI modified](detections/credential-access/application-redirect-uri-modified.md) |
| T1539 | Steal Web Session Cookie | [Anomalous token issuance after AiTM](detections/credential-access/anomalous-token-issuance-aitm.md) |
| T1550 | Use Alternate Authentication Material | [Anomalous token issuance after AiTM](detections/credential-access/anomalous-token-issuance-aitm.md) |
| T1556.006 | Modify Authentication Process: Multi-Factor Authentication | [MFA registration from unseen IP](detections/persistence/mfa-registration-from-unseen-ip.md), [Admin MFA registration for user](detections/persistence/admin-mfa-registration-for-user.md), [Authentication methods policy modified](detections/persistence/authentication-methods-policy-modified.md), [Temporary Access Pass created for user](detections/persistence/temporary-access-pass-created.md), [MFA disabled then sign-in from unseen IP](detections/persistence/mfa-disabled-then-signin-unseen-ip.md) |
| T1098 | Account Manipulation | [Cross-tenant access setting modified](detections/persistence/cross-tenant-access-setting-modified.md), [Sign-in from new country with sensitive operation](detections/privilege-escalation/sign-in-new-country-sensitive-operation.md), [Temporary Access Pass created for user](detections/persistence/temporary-access-pass-created.md), [Guest user type changed to member](detections/persistence/guest-user-type-changed-to-member.md) |
| T1098.001 | Additional Cloud Credentials | [SP credential addition by non-historical actor](detections/persistence/service-principal-credential-addition-nonhistorical.md), [SP credential addition followed by immediate sign-in](detections/credential-access/service-principal-credential-then-signin.md), [Service principal owner added](detections/persistence/service-principal-owner-added.md), [SP credential added by freshly privileged user](detections/persistence/fresh-role-granted-actor-sp-credential-added.md), [Federated identity credential added to SP](detections/persistence/service-principal-federated-identity-credential-added.md) |
| T1098.003 | Additional Cloud Roles | [Guest user added to privileged role](detections/privilege-escalation/guest-user-added-to-privileged-role.md), [Bulk role assignments in short window](detections/privilege-escalation/bulk-role-assignments.md), [Directory role assigned outside PIM](detections/privilege-escalation/directory-role-assigned-outside-pim.md), [High-privilege app role assigned to SP](detections/persistence/application-app-role-assigned-high-privilege.md), [Privileged role assigned to newly created account](detections/persistence/privileged-role-assigned-to-new-account.md) |
| T1136.003 | Create Account: Cloud Account | [Privileged role assigned to newly created account](detections/persistence/privileged-role-assigned-to-new-account.md) |
| T1078.004 | Valid Accounts: Cloud Accounts | [Sign-in from new country with sensitive operation](detections/privilege-escalation/sign-in-new-country-sensitive-operation.md), [PIM activation outside business hours](detections/defense-evasion/pim-activation-outside-business-hours.md), [Workload identity sign-in from new country](detections/credential-access/workload-identity-sign-in-new-country.md), [MFA disabled then sign-in from unseen IP](detections/persistence/mfa-disabled-then-signin-unseen-ip.md) |
| T1562.001 | Impair Defenses: Disable or Modify Tools | [Named location deleted or modified](detections/defense-evasion/named-location-deleted-or-modified.md), [Conditional Access policy disabled or deleted](detections/defense-evasion/conditional-access-policy-disabled.md) |
| T1484.002 | Domain Trust Modification | [Federated domain added to tenant](detections/defense-evasion/federated-domain-added.md) |

---

## Detection Index

### Credential Access

| Detection | Platform | Severity | PR |
|-----------|----------|----------|----|
| [OAuth consent to high-risk permission](detections/credential-access/oauth-consent-high-risk-permission.md) | Sentinel + SIGMA | High | [Azure-Sentinel#14276](https://github.com/Azure/Azure-Sentinel/pull/14276), [SigmaHQ#6012](https://github.com/SigmaHQ/sigma/pull/6012) |
| [OAuth consent to high-risk permission scope (90-day baseline)](detections/credential-access/oauth-consent-high-risk-permission-scope.md) | Sentinel | High | [Azure-Sentinel#14276](https://github.com/Azure/Azure-Sentinel/pull/14276) |
| [Anomalous token issuance after AiTM](detections/credential-access/anomalous-token-issuance-aitm.md) | Sentinel | High | [Azure-Sentinel#14276](https://github.com/Azure/Azure-Sentinel/pull/14276) |
| [Workload identity sign-in from new country](detections/credential-access/workload-identity-sign-in-new-country.md) | Sentinel | Medium | [Azure-Sentinel#14281](https://github.com/Azure/Azure-Sentinel/pull/14281) |
| [SP credential addition followed by immediate sign-in](detections/credential-access/service-principal-credential-then-signin.md) | Sentinel | High | [Azure-Sentinel#14299](https://github.com/Azure/Azure-Sentinel/pull/14299) |
| [OAuth application redirect URI modified](detections/credential-access/application-redirect-uri-modified.md) | Sentinel + SIGMA | Medium | [Azure-Sentinel#14307](https://github.com/Azure/Azure-Sentinel/pull/14307), [SigmaHQ#6025](https://github.com/SigmaHQ/sigma/pull/6025) |

### Persistence

| Detection | Platform | Severity | PR |
|-----------|----------|----------|----|
| [MFA registration from unseen IP](detections/persistence/mfa-registration-from-unseen-ip.md) | Sentinel | Medium | [Azure-Sentinel#14262](https://github.com/Azure/Azure-Sentinel/pull/14262) |
| [Admin registered MFA method for another user](detections/persistence/admin-mfa-registration-for-user.md) | Sentinel + SIGMA | High | [Azure-Sentinel#14262](https://github.com/Azure/Azure-Sentinel/pull/14262), [SigmaHQ#6012](https://github.com/SigmaHQ/sigma/pull/6012) |
| [Authentication methods policy modified](detections/persistence/authentication-methods-policy-modified.md) | SIGMA | High | [SigmaHQ#6012](https://github.com/SigmaHQ/sigma/pull/6012) |
| [Cross-tenant access setting modified](detections/persistence/cross-tenant-access-setting-modified.md) | SIGMA | High | [SigmaHQ#6012](https://github.com/SigmaHQ/sigma/pull/6012) |
| [SP credential addition by non-historical actor](detections/persistence/service-principal-credential-addition-nonhistorical.md) | Sentinel + SIGMA | Medium | [Azure-Sentinel#14276](https://github.com/Azure/Azure-Sentinel/pull/14276), [SigmaHQ#6016](https://github.com/SigmaHQ/sigma/pull/6016) |
| [High-privilege app role assigned to service principal](detections/persistence/application-app-role-assigned-high-privilege.md) | Sentinel + SIGMA | High | [Azure-Sentinel#14281](https://github.com/Azure/Azure-Sentinel/pull/14281), [SigmaHQ#6016](https://github.com/SigmaHQ/sigma/pull/6016) |
| [Privileged role assigned to newly created account](detections/persistence/privileged-role-assigned-to-new-account.md) | Sentinel | High | [Azure-Sentinel#14299](https://github.com/Azure/Azure-Sentinel/pull/14299) |
| [Temporary Access Pass created for user](detections/persistence/temporary-access-pass-created.md) | Sentinel | High | [Azure-Sentinel#14299](https://github.com/Azure/Azure-Sentinel/pull/14299) |
| [Guest user type changed to member](detections/persistence/guest-user-type-changed-to-member.md) | Sentinel + SIGMA | Medium | [Azure-Sentinel#14307](https://github.com/Azure/Azure-Sentinel/pull/14307), [SigmaHQ#6025](https://github.com/SigmaHQ/sigma/pull/6025) |
| [Service principal owner added](detections/persistence/service-principal-owner-added.md) | Sentinel + SIGMA | Medium | [Azure-Sentinel#14307](https://github.com/Azure/Azure-Sentinel/pull/14307), [SigmaHQ#6025](https://github.com/SigmaHQ/sigma/pull/6025) |
| [SP credential added by freshly privileged user](detections/persistence/fresh-role-granted-actor-sp-credential-added.md) | Sentinel | High | [Azure-Sentinel#14311](https://github.com/Azure/Azure-Sentinel/pull/14311) |
| [Federated identity credential added to service principal](detections/persistence/service-principal-federated-identity-credential-added.md) | Sentinel | Medium | [Azure-Sentinel#14311](https://github.com/Azure/Azure-Sentinel/pull/14311) |
| [MFA disabled then sign-in from unseen IP](detections/persistence/mfa-disabled-then-signin-unseen-ip.md) | Sentinel | High | [Azure-Sentinel#14311](https://github.com/Azure/Azure-Sentinel/pull/14311) |

### Privilege Escalation

| Detection | Platform | Severity | PR |
|-----------|----------|----------|----|
| [Guest user added to privileged Entra ID role](detections/privilege-escalation/guest-user-added-to-privileged-role.md) | Sentinel + SIGMA | High | [Azure-Sentinel#14240](https://github.com/Azure/Azure-Sentinel/pull/14240), [SigmaHQ#6012](https://github.com/SigmaHQ/sigma/pull/6012) |
| [Bulk role assignments in short window](detections/privilege-escalation/bulk-role-assignments.md) | Sentinel | Medium | [Azure-Sentinel#14262](https://github.com/Azure/Azure-Sentinel/pull/14262) |
| [Sign-in from new country with sensitive operation](detections/privilege-escalation/sign-in-new-country-sensitive-operation.md) | Sentinel | High | [Azure-Sentinel#14262](https://github.com/Azure/Azure-Sentinel/pull/14262) |
| [Directory role assigned outside PIM workflow](detections/privilege-escalation/directory-role-assigned-outside-pim.md) | Sentinel | High | [Azure-Sentinel#14281](https://github.com/Azure/Azure-Sentinel/pull/14281) |

### Defense Evasion

| Detection | Platform | Severity | PR |
|-----------|----------|----------|----|
| [Named location deleted or modified](detections/defense-evasion/named-location-deleted-or-modified.md) | Sentinel + SIGMA | Medium | [Azure-Sentinel#14240](https://github.com/Azure/Azure-Sentinel/pull/14240), [SigmaHQ#6012](https://github.com/SigmaHQ/sigma/pull/6012) |
| [Conditional Access policy disabled or deleted](detections/defense-evasion/conditional-access-policy-disabled.md) | Sentinel | High | [Azure-Sentinel#14240](https://github.com/Azure/Azure-Sentinel/pull/14240) |
| [PIM role activation outside business hours](detections/defense-evasion/pim-activation-outside-business-hours.md) | Sentinel | Medium | [Azure-Sentinel#14240](https://github.com/Azure/Azure-Sentinel/pull/14240) |
| [Federated domain added to tenant (Golden SAML)](detections/defense-evasion/federated-domain-added.md) | Sentinel | High | [Azure-Sentinel#14240](https://github.com/Azure/Azure-Sentinel/pull/14240) |

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
| [#14262](https://github.com/Azure/Azure-Sentinel/pull/14262) | Cross-source correlation hunting pack (3 queries) | Merged May 19, 2026 |
| [#14276](https://github.com/Azure/Azure-Sentinel/pull/14276) | Token abuse and OAuth consent hunting pack (3 queries) | Merged May 21, 2026 |
| [#14281](https://github.com/Azure/Azure-Sentinel/pull/14281) | Workload identity and privileged role hunting pack (3 queries) | Merged May 21, 2026 |
| [#14299](https://github.com/Azure/Azure-Sentinel/pull/14299) | Post-credential activity hunting pack (3 queries) | In review |
| [#14307](https://github.com/Azure/Azure-Sentinel/pull/14307) | Identity boundary expansion hunting pack (3 queries) | In review |
| [#14311](https://github.com/Azure/Azure-Sentinel/pull/14311) | Attack chain correlation hunting pack (3 queries) | In review |
| [#14334](https://github.com/Azure/Azure-Sentinel/pull/14334) | Fix modifiedProperties displayName in OAuthConsentToHighRiskPermissionScope (bugfix) | In review |
| [#14335](https://github.com/Azure/Azure-Sentinel/pull/14335) | Account takeover hunting pack: device code phishing, new SP + admin consent, bulk password reset (3 queries) | In review |
| [#14336](https://github.com/Azure/Azure-Sentinel/pull/14336) | BadUSB PowerShell Run dialog hunting query (HID injection, DeviceProcessEvents) | In review |
| [#14339](https://github.com/Azure/Azure-Sentinel/pull/14339) | Auth anomaly and privilege abuse hunting pack: legacy auth sign-in, guest initiator, password reset pivot (3 queries) | In review |

### SigmaHQ/sigma

| PR | Description | Status |
|----|-------------|--------|
| [#6012](https://github.com/SigmaHQ/sigma/pull/6012) | Azure Entra ID identity attack detections (6 rules) | In review |
| [#6016](https://github.com/SigmaHQ/sigma/pull/6016) | SP credential addition and admin consent high-risk permission (2 rules) | In review |
| [#6024](https://github.com/SigmaHQ/sigma/pull/6024) | Temporary Access Pass creation detection | In review |
| [#6025](https://github.com/SigmaHQ/sigma/pull/6025) | Identity boundary expansion rules: guest-to-member, SP owner, redirect URI (3 rules) | In review |
| [#6028](https://github.com/SigmaHQ/sigma/pull/6028) | BadUSB PowerShell Run dialog detection (HID injection via explorer.exe parent) | In review |

### splunk/security_content

| PR | Description | Status |
|----|-------------|--------|
| [#4091](https://github.com/splunk/security_content/pull/4091) | Azure AD Entra ID identity attack detections: TAP creation, guest-to-member, federated identity credential (3 analytics) | In review |

### elastic/detection-rules

| PR | Description | Status |
|----|-------------|--------|
| [#6168](https://github.com/elastic/detection-rules/pull/6168) | Entra ID identity attack rules: TAP creation, guest-to-member, OAuth redirect URI (3 rules) | In review |

### IBM/qradar-mcp

| PR | Description | Status |
|----|-------------|--------|
| [#4](https://github.com/IBM/qradar-mcp/pull/4) | Enable Ariel search Phase 2: AQL query execution and saved search management (8 tools + 4 resources) | In review |

---

## Open Source Contributions

All content in this repo has been contributed upstream to the community:

- **Microsoft Azure-Sentinel** - [github.com/Azure/Azure-Sentinel](https://github.com/Azure/Azure-Sentinel)
- **SigmaHQ** - [github.com/SigmaHQ/sigma](https://github.com/SigmaHQ/sigma)
- **Elastic detection-rules** - [github.com/elastic/detection-rules](https://github.com/elastic/detection-rules)
- **Splunk security_content** - [github.com/splunk/security_content](https://github.com/splunk/security_content)
- **IBM QRadar MCP** - [github.com/IBM/qradar-mcp](https://github.com/IBM/qradar-mcp)
- **flipper-purple-team** - [github.com/descambiado/flipper-purple-team](https://github.com/descambiado/flipper-purple-team)

---

## Author

**descambiado** - SOC Analyst and Detection Engineer. Writing Entra ID identity attack detections across Microsoft Sentinel, Elastic SIEM, Splunk, SigmaHQ, and contributing to open-source security tooling.

[github.com/descambiado](https://github.com/descambiado)
