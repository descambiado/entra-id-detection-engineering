# Federated Identity Credential Added to Service Principal

## Technique
**MITRE ATT&CK**: [T1098.001 — Additional Cloud Credentials](https://attack.mitre.org/techniques/T1098/001/)  
**Tactic**: Persistence

## What the attacker is doing

Workload identity federation lets an external workload — a GitHub Actions workflow, an AWS role, a Kubernetes service account — authenticate as an Entra ID service principal by presenting an OIDC token from its own IdP. Entra ID validates the token against the issuer URL and subject claim configured in the federated credential, then issues an Entra access token for the SP.

From a defense perspective, this is a secretless credential: there is no `passwordCredential` or `keyCredential` to rotate, expire, or detect with secrets scanning. The SP gains a persistent authentication path tied to the external IdP rather than anything that lives in the tenant.

Attacker abuse pattern:

1. Attacker compromises an account with Application Administrator rights (or SP ownership)
2. Attacker adds a federated credential pointing to an attacker-controlled OIDC IdP with a subject claim they control
3. Attacker's workload presents a token to the external IdP, receives an OIDC JWT, exchanges it with Entra ID for an SP access token
4. SP access token is valid, passes all Conditional Access policies scoped to workload identities, no secret ever touches the tenant

This technique is particularly relevant to CI/CD supply chain compromise: an attacker who can push to a GitHub repository can configure a workflow that impersonates an Entra SP if a federated credential with a permissive `sub` claim exists.

## Why standard detections miss it

Most SP credential monitoring watches `Add service principal credentials` — the operation for password and certificate credentials. Federated credential additions produce `Update service principal` with a modification to `FederatedIdentityCredentials` in `modifiedProperties`, a different operation name that bypasses those detections entirely.

The event is not noisy. In most tenants, federated credential additions are rare and should be reviewed when they appear.

## Detection

### KQL (Microsoft Sentinel)

```kql
let timeframe = 1d;
AuditLogs
| where TimeGenerated >= ago(timeframe)
| where OperationName =~ "Update service principal"
| where Result =~ "success"
| mv-expand ModProp = TargetResources[0].modifiedProperties
| where tostring(ModProp.displayName) =~ "FederatedIdentityCredentials"
| extend OldCreds     = tostring(ModProp.oldValue)
| extend NewCreds     = tostring(ModProp.newValue)
| extend TargetSpName = tostring(TargetResources[0].displayName)
| extend TargetSpId   = tostring(TargetResources[0].id)
| extend ActorUpn     = tostring(InitiatedBy.user.userPrincipalName)
| extend ActorApp     = tostring(InitiatedBy.app.displayName)
| extend Actor        = iff(isnotempty(ActorUpn), ActorUpn, ActorApp)
| extend ActorIp      = iff(
      isnotempty(tostring(InitiatedBy.user.ipAddress)),
      tostring(InitiatedBy.user.ipAddress),
      tostring(InitiatedBy.app.ipAddress))
| extend AccountName      = iff(ActorUpn has "@",
      tostring(split(ActorUpn, "@")[0]), Actor)
| extend AccountUPNSuffix = iff(ActorUpn has "@",
      tostring(split(ActorUpn, "@")[1]), "")
| project
    TimeGenerated,
    TargetSpName,
    TargetSpId,
    OldCreds,
    NewCreds,
    Actor,
    AccountName,
    AccountUPNSuffix,
    ActorIp,
    CorrelationId
| sort by TimeGenerated desc
```

**Contributed**: [Azure/Azure-Sentinel#14311](https://github.com/Azure/Azure-Sentinel/pull/14311)

## False Positives

- Platform teams configuring GitHub Actions OIDC federation as part of planned CI/CD setup
- Infrastructure-as-code pipelines that provision federated credentials for workloads during deployment
- Terraform or Bicep deployments that manage SP federated credentials as part of standard IaC

**Analyst note**: Inspect `NewCreds` for the issuer URL and subject claim. A legitimate federation points to a known IdP (`token.actions.githubusercontent.com`, a known Kubernetes cluster OIDC endpoint, etc.) with a specific, narrow subject claim. A broad subject wildcard or an unknown issuer URL is the key indicator. Also compare `OldCreds` against `NewCreds` — a net-new credential where none previously existed is higher risk than a modification to an existing one.

## Investigation Steps

1. Parse `NewCreds` to extract `issuer`, `subject`, and `audiences` from the JSON array
2. Verify the issuer is a known, trusted OIDC endpoint — unknown issuers require immediate escalation
3. Check whether the subject claim is specific (e.g., `repo:org/repo:ref:refs/heads/main`) or permissive (wildcards, broad patterns)
4. Identify what permissions the target SP holds: Entra ID portal > Enterprise applications > [SP name] > Permissions
5. Check `AADServicePrincipalSignInLogs` for sign-ins using this SP after the federated credential was added: `AADServicePrincipalSignInLogs | where ServicePrincipalId == "<sp-id>" | where TimeGenerated > <cred-add-time>`
6. If the SP has broad permissions and the issuer/subject is unknown, treat as active compromise

## References

- [Microsoft: Workload identity federation overview](https://learn.microsoft.com/en-us/entra/workload-id/workload-identity-federation)
- [Microsoft: Configure federated credentials for a service principal](https://learn.microsoft.com/en-us/entra/workload-id/workload-identity-federation-create-trust)
- [GitHub: About security hardening with OpenID Connect](https://docs.github.com/en/actions/security-for-github-actions/security-hardening-your-deployments/about-security-hardening-with-openid-connect)
- [MITRE T1098.001](https://attack.mitre.org/techniques/T1098/001/)
