# Does the Entra diagnostic-settings export carry the en dash?

**Captured 2026-09-07** from `law-detection-lab`, a live Log Analytics workspace fed by Entra ID
diagnostic settings. This is the same export path that Elastic's Azure integration consumes.

## The question, and why it was worth answering before saying anything

Entra Graph (`/auditLogs/directoryAudits`) returns:

```
'Update application – Certificates and secrets management '     U+2013, trailing space
```

Two production rules assume a plain hyphen instead:

- SigmaHQ `azure_app_credential_added.yml`, on `properties.message`, merged as PR #6247
- Elastic `persistence_entra_id_application_credential_modification.toml` (2020), on
  `azure.auditlogs.operation_name`, verified byte by byte as U+002D

The obvious reading is "both are wrong". That reading is too fast. A maintainer merged the SigmaHQ
one knowingly, and the two rules target different representations from Graph. Claiming a bug in
Elastic's ruleset on Graph evidence alone would be an assumption, which is the exact objection that
closed five PRs in May.

So the question was narrowed to something a workspace can answer: **what character does
`OperationName` actually hold in the table the export writes to?**

## Result

```
OperationName : "Create application – Certificates and secrets management "
hasEnDash     : True
hasHyphen     : False
endsWithSpace : True
```

The export carries **U+2013 and the trailing space**, the same as Graph. It is not normalised to a
hyphen on the way out.

Control on the same rows:

```
AuditLogs | where OperationName == 'Update application - Certificates and secrets management' | count
  -> 0
```

## What this does and does not establish

**Establishes:** the diagnostic-settings export preserves the en dash. Any rule matching that
operation name with a plain hyphen, against this representation, cannot match.

**Does not establish, yet:** the string above is the `Create application` variant. Elastic's rule
targets the `Update application` variant. Those are separate strings and the second one has to be
observed in this table before the claim is made about Elastic's rule specifically. That event has
been generated and is pending ingestion.

**Does not establish at all:** anything about SigmaHQ's merged rule. That one selects on
`properties.message`, a different field, in the convention this repository deliberately excludes from
its audit. Do not extend this result to it.

## Ingestion timing, recorded because it caused a wrong hypothesis

Diagnostic setting created 14:16Z, first row visible 15:23Z: **67 minutes**, against the 15 minutes
Microsoft documents. During the wait the hypothesis "Spain Central is a new region the export does
not support" was raised and tested with a second workspace in North Europe. **That hypothesis was
wrong.** Both regions received data within two minutes of each other. The delay was first-time export
setup, nothing else.

---

Tool versions, environment and re-run instructions: [PROVENANCE.md](PROVENANCE.md)

---

## Addendum 2026-09-12: Microsoft's own documentation is a fourth representation

The audit activity reference at
`learn.microsoft.com/entra/identity/monitoring-health/reference-audit-activities` lists the operation
as:

```
Update application - Certificates and secrets management
```

**U+002D HYPHEN-MINUS, no trailing space.** That is not what the telemetry emits. The Graph response
and the diagnostic-settings export both carry U+2013 EN DASH plus a trailing space, measured against
a live workspace on 2026-09-07.

So Microsoft's documentation disagrees with Microsoft's own logs, and that is a fourth form of the
same operation name alongside portal, Graph and export.

**This explains the rules rather than excusing them.** Both SigmaHQ's `azure_app_credential_added.yml`
and Elastic's `persistence_entra_id_application_credential_modification.toml` use the hyphen. Neither
author was careless: they wrote the value the vendor publishes. The value the vendor publishes is not
the value the vendor emits.

Worth stating in that framing if this is ever written up, because "two projects copied a wrong string
from the official reference" is a different and more useful claim than "two projects made a typo".
