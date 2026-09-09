# Candidates that are NOT confirmed

**Status as of 2026-09-09.** Nothing in this file is a finding. It is here so the reasoning is not
lost and so nobody, including a future me, mistakes it for evidence.

The rule that governs this file: **absence from Microsoft's published activity list proves nothing**,
because that list is demonstrably incomplete. `Add eligible member (permanent)` is missing from it
while Microsoft's own Sentinel analytic rule queries that exact string. A candidate is promoted only
by an executed test showing the rule's value returns nothing where the real one returns the row.

## Discarded outright

**`azure_priviledged_role_assignment_add.yml`** selects `Add eligible member (permanent)` and
`Add eligible member (eligible)`. Both absent from the published list, **but Microsoft's own
`Solutions/Business Email Compromise - Financial Fraud/Analytic Rules/UserAddedtoAdminRole.yaml`
queries both strings verbatim.** The rule is almost certainly fine and the reference is incomplete.
**Not a finding. Do not report it.**

## Open candidates, ranked by how much non-list evidence exists

### 1. `azure_subscription_permissions_elevation_via_auditlogs.yml` (strongest)

```yaml
Category: 'Administrative'
OperationName: 'Assigns the caller to user access admin'
```

Two independent problems that point at the same explanation:

- `Administrative` is not among the **47** categories Microsoft documents for Entra audit logs. It is
  the well known category of the **Azure Activity Log**, a different source.
- `Assigns the caller to user access admin` is the *description* of the Activity Log operation
  `Microsoft.Authorization/elevateAccess/action`, not an activity name.

Microsoft documents the Entra equivalents under category `AzureRBACRoleManagementElevateAccess`:

```
User has elevated their access to User Access Administrator for their Azure Resources
The role assignment of User Access Administrator has been removed from the user
```

So the coherent reading is that the rule was written against Azure Activity Log semantics and filed
under the Entra `auditlogs` logsource. **Still a candidate:** elevating access is a privileged
operation and was not performed to test this. Neither value appears anywhere in Azure-Sentinel,
elastic/detection-rules or the rest of SigmaHQ.

### 2. `azure_pim_activation_approve_deny.yml`

Selects `Request Approved/Denied`, a single string with a slash. Microsoft documents two separate
activities, `Add member to role request approved (PIM activation)` and
`... request denied (PIM activation)`. The string appears nowhere outside its own rule.
**Candidate.** Needs a PIM activation approval event, which the az CLI token cannot create
(`RoleEligibilitySchedule.ReadWrite.Directory` not granted, and deliberately not granted).

### 3. `azure_priviledged_role_assignment_bulk_change.yml` (weakest)

Selects `Remove eligible member (permanent)` and `(eligible)`. Absent from the list and used nowhere
else, **but it is the exact mirror of the Add rule that was just discarded**, and Microsoft's naming
is symmetric. If the Add strings are real, these probably are too. **Treat as discarded unless an
event says otherwise.**

## What would settle 1, 2 and 3

Generating the events. For the PIM ones that is a few clicks in the portal, or granting the lab app
`RoleManagement.ReadWrite.Directory`, which is a strong permission and has not been granted. For the
elevation one it means elevating a real account's access, which is not worth doing to test a rule.

Tool versions and environment: [PROVENANCE.md](PROVENANCE.md)
