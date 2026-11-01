# Open PR #6278 claims managed identities log `Update service principal` in AuditLogs. Our own test says they don't.

> **RESOLVED, 2026-10-26, later the same day.** earbona23 was right. Our own test had a real gap:
> we added a federated credential to a **user-assigned managed identity via the Azure Resource
> Manager API** (`PUT .../Microsoft.ManagedIdentity/userAssignedIdentities/{name}/federatedIdentityCredentials/{credName}`)
> and watched only `AuditLogs`, concluding nothing landed there. A later, more careful re-read of the
> same tenant's `directoryAudits` found a real event 11 seconds after that write: `Update service
> principal`, actor `Managed Service Identity`, target type `ServicePrincipal`, with
> `FederatedIdentityCredentials` in `modifiedProperties`. It was there the whole time; our polling
> window or filter missed it, and we declared the table empty without exhausting the search. PR
> #6278's claim stands: managed identities do write to `AuditLogs` as `Update service principal`.
> This also means the parallel finding against our own merged `#14311` content needed correcting
> from "zero coverage on both paths" to "partial coverage" (see
> `evidence/azure-sentinel-14311-federated-credential-wrong-operation.md`, corrected the same day).
> The rest of this file is kept as the historical record of the wrong conclusion and how it was
> reached, not as a live claim.

**Originally: not resolved. A disagreement between two independently-measured claims, documented so
neither gets acted on until it is.**

## The two claims

**SigmaHQ PR #6278** (earbona23, open since 2026-09-06, last updated 2026-10-25, so actively
maintained), `azure_app_federated_identity_credential_added.yml`:

> `OperationName` is `Update application` (app registration) or `Update service principal` (service
> principal / managed identity) ... Verified the exact operation name (`Update service principal`)
> and the modified-property display name (`FederatedIdentityCredentials`) against a real Entra
> audit-log sample.

**Our own finding, same session, 2026-10-26**
(`evidence/azure-sentinel-14311-federated-credential-wrong-operation.md`): created a disposable
user-assigned managed identity, added a federated credential to it through the only API that exists
for that, `PUT .../Microsoft.ManagedIdentity/userAssignedIdentities/{name}/federatedIdentityCredentials/{credName}`
(Azure Resource Manager, not Graph), and found:

- `AuditLogs` / Graph `directoryAudits`: nothing after the identity's own creation event, no matter
  how long the wait.
- Azure Activity Log: `Microsoft.ManagedIdentity/userAssignedIdentities/federatedIdentityCredentials/write`,
  succeeded. A different table entirely.

If that holds, no `OperationName` value in `AuditLogs`, `Update service principal` or anything else,
could ever catch a managed identity's federated credential addition, because the event is not in
that table.

## What could make both true at once, not yet checked

- **System-assigned vs user-assigned.** We tested user-assigned only. A system-assigned managed
  identity, tied 1:1 to a resource like a VM, might be provisioned or modified through a different
  path that does write to `AuditLogs`. Untested.
- **A different credential-addition path.** We used the ARM-specific endpoint because it is the only
  one Microsoft documents for managed identities. If #6278's author found or used a different route
  (Graph directly against the servicePrincipal object, even if undocumented), the two tests may
  simply not be measuring the same action.
- **A stale or synthetic "real" sample.** Possible on either side; neither this file nor #6278 claims
  the other is wrong, both claims cite a real capture.

## What this is not

Not a claim that #6278 is incorrect. Not a claim that our own #14311 finding is incorrect either.
Two real, specific, differently-scoped tests that disagree on one point, surfaced so the disagreement
is visible before either gets acted on (a PR comment, a fix to #14311, or anything else) on the
strength of only one side.

## What would settle it

Test a system-assigned managed identity specifically, and ask whether #6278's author can share which
Entra object type and credential path they captured. Not done today.
