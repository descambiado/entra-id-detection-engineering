# `ServicePrincipalFederatedIdentityCredentialAdded.yaml` selects on the wrong operation

> **This is a finding about content already merged and live in a public, widely-used repository**
> (`Azure/Azure-Sentinel`, our own PR #14311). It is not a draft. Treat the severity accordingly:
> anyone running this detection today believes they are covered against federated-credential
> persistence (the Midnight Blizzard technique) and, on the evidence below, is not.

> **CORRECCION 2026-10-26 (leida directamente de `auditLogs/directoryAudits` del tenant, no de memoria).**
> Lo de abajo dice que el PR #14311 tiene "cobertura cero en los dos caminos". **Es falso para el camino de identidad administrada.**
> Eventos reales del 24/10:
> - 13:41:14 UTC `Update application`, objetivo `Application`, propiedad `FederatedIdentityCredentials`: **camino de app registration, la regla fusionada NO lo ve** (confirmado).
> - 13:47:07 UTC `Update service principal`, actor `Managed Service Identity`, objetivo `ServicePrincipal` (`lab-test-mi-...`), propiedad `FederatedIdentityCredentials`:
>   **camino de identidad administrada, SI llega a `AuditLogs`, 11 segundos despues del `Add service principal`, y la regla fusionada SI lo ve** (ejecutada: 1 fila).
> La sesion anterior no vio ese evento (miro solo el `Add service principal` y la tabla de actividad de Azure). Cobertura real de la regla fusionada: **parcial**, no cero.
> Arreglo ejecutado contra esos mismos eventos: la consulta antigua devuelve 1 fila, la corregida (`Update application` y `Update service principal`) devuelve 2.
> Las secciones siguientes se conservan como historia; donde digan "cero" o que la identidad administrada no llega a `AuditLogs`, vale esta correccion.

> **RESOLVED, 2026-10-28.** The operation filter was fixed in Azure-Sentinel #15444 (opened 2026-10-27, merged 2026-10-28): it now matches both `Update application` and `Update service principal`. Measured on the real events of 2026-10-24: the old query returned 1 row, the fixed one returns 2.

**Finding date:** 2026-10-24
**Rule:** `Hunting Queries/AuditLogs/ServicePrincipalFederatedIdentityCredentialAdded.yaml`
**Title:** Federated identity credential added to Entra ID service principal
**PR:** [Azure/Azure-Sentinel#14311](https://github.com/Azure/Azure-Sentinel/pull/14311) (merged)

## Claim

The rule selects `OperationName in~ ("Update service principal")`. The only Microsoft
Graph-documented, API-supported way to add a federated identity credential is against the
**application** object, not the service principal, and that path emits `OperationName: "Update
application"`. The rule, as merged, is blind to the real-world path it was written to catch.

## How it was found

Not by re-reading the KQL. By generating the actual action against a live tenant and reading what
Entra really emits, the same discipline every finding in this directory is held to.

1. Created a disposable app registration (`lab-test-federated-cred-*`).
2. Added a federated identity credential to it via the only Graph endpoint that exists for this:
   `POST /applications/{id}/federatedIdentityCredentials`, matching the exact setup an attacker (or
   a legitimate GitHub Actions OIDC pipeline) would use.
3. Captured the real event via `auditLogs/directoryAudits`:

```json
{
  "activityDisplayName": "Update application",
  "category": "ApplicationManagement",
  "operationType": "Update",
  "targetResources": [
    {
      "type": "Application",
      "modifiedProperties": [
        { "displayName": "FederatedIdentityCredentials", "newValue": "[{\"Name\":\"lab-test-fed-cred\", ...}]" },
        { "displayName": "Included Updated Properties", "newValue": "\"FederatedIdentityCredentials\"" }
      ]
    }
  ]
}
```

`OperationName` is `Update application`. Not `Update service principal`. The `modifiedProperties`
shape the rule already expects (`displayName == "FederatedIdentityCredentials"`) is otherwise
correct; only the `OperationName` filter and the `targetResources[0].type` assumption are wrong.

4. Confirmed against Microsoft's own API reference
   (`learn.microsoft.com/en-us/graph/api/resources/federatedidentitycredentials-overview`), which
   states federated identity credentials can be added "per **application object** or user-assigned
   managed identity" and documents only the `applications/{id}/federatedIdentityCredentials`
   endpoint. No `servicePrincipals/{id}/federatedIdentityCredentials` endpoint exists in the public
   API.
5. Deleted the test app immediately after capture. Nothing left in the tenant.

## What this does and does not prove

**Proven, with a real executed event and corroborating Microsoft documentation:** the standard,
documented, API-supported path for adding a federated identity credential to an app registration
(the GitHub Actions / CI-CD scenario the rule's own description names) produces `Update
application`, and the merged rule does not match that value.

**UPDATE, same session, the managed identity path is now checked too, and it is worse.** Created a
disposable user-assigned managed identity and added a federated credential to it through the only
API that exists for that: `PUT .../Microsoft.ManagedIdentity/userAssignedIdentities/{name}/federatedIdentityCredentials/{credName}`,
an Azure Resource Manager endpoint, not Microsoft Graph.

Checked Entra `AuditLogs` for any event tied to the managed identity's service principal: only the
one `Add service principal` event from the identity's own creation. Nothing after the credential
was added, no matter how long the wait.

Checked Azure Activity Log for the same window instead:

```
Microsoft.ManagedIdentity/userAssignedIdentities/federatedIdentityCredentials/write | Succeeded
```

**The managed identity path does not write to `AuditLogs` at all.** It is an Azure Resource Manager
operation, logged to Activity Log, a completely different table than the one this rule queries. No
`OperationName` value on `AuditLogs`, correct or not, could ever catch it.

So the rule is wrong for both documented paths, for two different reasons that both lead to zero
coverage:
- **App registration** (the GitHub Actions / CI-CD scenario the rule's description names): wrong
  table filter value. `AuditLogs` has the event, under `Update application`, not `Update service
  principal`.
- **Managed identity**: wrong table entirely. The event is in Activity Log, not `AuditLogs`, so no
  `OperationName` fix inside the existing query can reach it; it needs a second query against a
  different data source, or a deliberate decision to leave managed identities out of scope and say
  so.

Test app and test managed identity both deleted immediately after capture. Nothing left in the
tenant.

## Suggested fix, not yet written

Two separate changes, because the two paths fail for two different reasons:

1. **App registration (fixes the common CI/CD case):** correct the operation filter.
   ```kql
   | where OperationName in~ ("Update application")
   ```
   `targetResources[0].type` will be `Application`, not `ServicePrincipal`; `TargetSpName` /
   `TargetSpId` in the existing query should be renamed or the field extraction adjusted
   accordingly, since they currently assume a service principal target.
2. **Managed identity:** cannot be fixed inside this query. It needs either a second,
   Activity-Log-based detection (`Microsoft.ManagedIdentity/userAssignedIdentities/federatedIdentityCredentials/write`),
   or an explicit, stated decision to leave managed identities out of this rule's scope and say so
   in its description, rather than implying coverage the rule does not have.

## What happens next

This is David's own already-merged content in a repository he does not solely control. The right
channel (PR fixing the operation filter, an issue first, or a comment on the original PR) is his
call, not something to act on unilaterally. Nothing opened, nothing commented, nothing published.

Tool versions and environment: [PROVENANCE.md](PROVENANCE.md).
