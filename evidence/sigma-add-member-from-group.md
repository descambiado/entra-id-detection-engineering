# `azure_group_user_addition_ca_modification.yml` cannot fire

**Finding date:** 2026-09-08
**Rule:** `rules/cloud/azure/audit_logs/azure_group_user_addition_ca_modification.yml`
**Title:** User Added To Group With CA Policy Modification Access
**Authors:** Mark Morowczynski '@markmorow', Thomas Detzner '@tdetzner', 2022-08-04

## Claim

The rule selects on `Add member from group`. Entra does not emit that operation. It emits
`Add member to group` for the action the rule describes, and `Remove member from group` for the
opposite one. The value in the rule is a splice of the two, so the rule has never matched.

## How it was found, and why that matters

Not by generating the event. By checking every operation name in the `service: auditlogs` rules
against the 907 activity names Microsoft publishes in the audit activity reference. That check needs
no events at all, which is the point: it closes the half of the coverage problem that event
generation cannot reach, across the whole corpus in one pass.

The event was generated afterwards, to turn a documentary claim into an executed one.

## Documentary evidence

Microsoft's audit activity reference, group membership entries:

```
Add member to group
Remove member from group
Remove eligible member from group
```

`Add member from group` does not appear.

## Executed evidence

Created a security group in a real tenant, added a member, and queried the Log Analytics workspace
fed by Entra diagnostic settings:

```
AuditLogs | where OperationName == 'Add member from group' | count   ->  0 rows
AuditLogs | where OperationName == 'Add member to group'   | count   ->  1 row
```

```
Category         OperationName        Result   TimeGenerated
GroupManagement  Add member to group  success  2026-09-08T12:59:13Z
```

The positive control is what makes the zero mean something: the same table, the same moment, one
string returns nothing and the other returns the event.

## The rule's own text agrees it is a copy-paste error

```yaml
title: User Added To Group With CA Policy Modification Access
description: Monitor and alert on group membership additions of groups that have CA policy modification access
detection:
    selection:
        properties.message: Add member from group
falsepositives:
    - User removed from the group is approved
```

The title says added, the description says additions, and the false positive line still describes a
**removal**. The sibling rule `azure_group_user_removal_ca_modification.yml` selects on
`Remove member from group`, which is correct. This rule was copied from it, `Remove` was changed to
`Add`, and `from group` was left behind along with the false positive text.

## Why it matters

The rule watches membership changes on groups that hold Conditional Access modification rights.
Adding yourself to such a group is a privilege escalation step, and it is the direction the rule was
written to catch. The removal half is covered. The addition half has been silent since August 2022.

## What is NOT claimed

Whether the rule fires depends on the backend resolving `properties.message` at all, which is a
separate convention question this repository's audit deliberately excludes. The finding here is
narrower and survives that question: **whatever field it resolves to, the value it compares against
is not a string Entra emits.**

---

Tool versions, environment and re-run instructions: [PROVENANCE.md](PROVENANCE.md)
