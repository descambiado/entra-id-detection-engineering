# SigmaHQ #6247 replaced a correct en dash with a hyphen, and both citations that justified it are void

**Finding date:** 2026-09-13
**Rule:** SigmaHQ `rules/cloud/azure/audit_logs/azure_app_credential_added.yml`
**Our PR:** SigmaHQ #6247, **merged 2026-09-03**, author `descambiado`
**Status:** not reported. This reverses one of our own merged PRs, so the call is David's.

## What #6247 did

```diff
-            - Update application – Certificates and secrets management     (U+2013, en dash)
-            - Update Service principal/Update Application
+            - 'Update application - Certificates and secrets management'   (U+002D, hyphen)
+            - 'Update Service principal/Update Application'
```

## What the diagnostic settings export actually emits, measured today

Live Log Analytics workspace `law-detection-lab`, fed by the `microsoft.aadiam` diagnostic
setting. Row confirmed to have arrived through that pipeline: `Resource = Microsoft.aadiam`.

```
OperationName        : 'Update application – Certificates and secrets management '
ActivityDisplayName  : identical
pos 19               : U+2013 EN DASH
trailing space       : True
```

Decisive counts on that same live data:

| Query | Rows |
|---|---|
| `OperationName == 'Update application - Certificates and secrets management'` (what #6247 set) | **0** |
| same with `=~`, so case is excluded as the cause | **0** |
| `OperationName == 'Update application ' + U+2013 + ' Certificates and secrets management '` | **1** |
| `OperationName == 'Update Service principal/Update Application'` (the other value in the rule) | **0** |
| `OperationName has_any ('Add service principal','Certificates and secrets management')` (Microsoft) | **7** |

**Both values in the merged rule return zero.**

## The two citations in the #6247 comment, checked one by one

The comment at `SigmaHQ/sigma#6247#issuecomment-5463002942` argued the hyphen was right for the
diagnostic shape on two grounds. Neither survives.

**1. "Microsoft's own Entra ID solution uses U+002D."** It does not. Both files cited,
`Solutions/Microsoft Entra ID/Analytic Rules/NewAppOrServicePrincipalCredential.yaml` and its
`NRT_` twin, match like this:

```kql
| where OperationName has_any ("Add service principal", "Certificates and secrets management")
  // captures ... and "Update application - Certificates and secrets management" events
```

The hyphen appears **only inside the `//` comment**. The matched value is the dash free fragment.
Microsoft deliberately avoids the dash. Reading the comment as if it were the predicate is what
produced the citation. Authorship checked, `v-rusraut` and `Diana Damenova`, 2023 to 2024, no
involvement of ours.

**2. "Elastic's rule agrees."** It did, and five days later we filed
**elastic/detection-rules #6749** to change that exact value from hyphen to en dash plus trailing
space, on the grounds that the hyphen cannot match. The Sigma PR cites as corroboration the very
string our own later PR calls a defect. The two positions cannot both hold.

## What is and is not proven

**Measured:** Graph `activityDisplayName`, Log Analytics `OperationName`, Log Analytics
`ActivityDisplayName`. Three fields, all carrying U+2013 and a trailing space.

**Not measured:** an Event Hub payload's `properties.message`, which is the field the Sigma rule
names. We have no Event Hub.

So the claim here is deliberately not "the hyphen is proven wrong for Event Hub". It is:
**the evidence that justified changing it does not support the change, and every representation
anyone has actually put a byte counter on carries the en dash.** The rule was moved off a value
that matches real telemetry onto one that matches nothing in any measured representation.

The carve out written in `elastic-app-credential-rule-cannot-fire.md`, that nothing in that file
applies to the Sigma rule because `properties.message` is a different field, is weaker than it
looked. Elastic's `azure.auditlogs.operation_name` is fed from Event Hub, and #6749 asserts that
value carries the en dash.

## The fix that makes the question moot

Adopt Microsoft's own approach, match the fragment that contains no dash at all:

```yaml
    selection:
        properties.message|contains: 'Certificates and secrets management'
```

Three things at once:

1. No dependence on which dash any representation emits, and none on the trailing space.
2. It also catches `Create application – Certificates and secrets management `, the single call
   path where an application is created with credentials. **2 real events in our own tenant, and
   no rule in SigmaHQ or Elastic covers it.** That gap was recorded on 2026-09-07 and is still open.
3. It is defensible in public without argument, because it is what Microsoft ships.

Live check of the proposed selection against our data: `contains 'Certificates and secrets
management'` returns **3** rows, 1 `Update application` and 2 `Create application`. The current
merged rule returns **0**.

## Blast radius in our own merged work

Five hunting queries merged into `Azure/Azure-Sentinel` in May 2026 under `descambiado` carry the
same hyphenated value. Impact is **not** uniform and must not be reported as if it were.

| File | Shape | Effect |
|---|---|---|
| `ServicePrincipalCredentialAdditionByRareActor.yaml` | `credOps` = 2 values | loses the app registration path, keeps `Add service principal credentials` |
| `ServicePrincipalCredentialAdditionByNonHistoricalActor.yaml` | same 2 values, in baseline **and** detection | same, on both halves |
| `FreshRoleGrantedActorSpCredentialAdded.yaml` | same 2 values | same |
| `PasswordResetThenPrivilegedOperation.yaml` | 1 of ~8 privileged ops | loses one operation, query still works |
| `GuestAccountPrivilegedOperation.yaml` | 1 of ~8 privileged ops | same |

None of the five is dead. `Add service principal credentials` is real and confirmed live, 1 row.
The accurate statement is **partial blindness on the app registration credential path**, which is
the ordinary portal route, not "the queries do not fire".

One Microsoft file has it too, `MultipleDataSources/DormantServicePrincipalUpdateCredsandLogsIn.yaml`,
Pete Bryan, 2021. Same partial effect, and not ours to fix in the same breath.

## Trap checks run before writing this

- Open PRs in SigmaHQ touching `azure_app_credential_added.yml`: **none**. Searched by filename and
  by the literal string. The two PRs the string search returned, #6142 and #6278, do not contain it
  in their diffs or conversations.
- Circular citation: authorship of every Microsoft file cited was checked with `git log`. The five
  hunting queries that are ours are listed as ours and excluded from the evidence side.
- Case: excluded as a cause by running `=~`, which also returns 0.
