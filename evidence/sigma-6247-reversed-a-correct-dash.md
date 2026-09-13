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

## The fix, prepared 2026-09-13 and not sent

Branch `fix-app-credential-added-fragment-match` on `descambiado/sigma`, commit `d2946fa`, based on
upstream master `5c9b217`. **One file, +6 / -4.**

```yaml
    selection:
        # Two fragments on purpose: the export writes U+2013 plus a trailing space here, some
        # vendor content writes U+002D. https://github.com/SigmaHQ/sigma/pull/6247#issuecomment-5463002942
        properties.message|contains|all:
            - 'Update application'
            - 'Certificates and secrets management'
    condition: selection
```

**Why `contains|all` of two fragments and not simply the en dash back.** We measured Log Analytics
and Graph, not an Event Hub payload, and `properties.message` is the Event Hub shape. Two fragments
make that question moot. Keeping `Update application` as one of them also holds the rule inside its
own title: the bare fragment alone would pull in `Create application – ...`, a new application rather
than an existing one. Live: proposal 1 row, bare fragment 3, current rule 0.

`|contains|all` on `properties.message` is already the convention in that folder, so this is not a
novel construction.

### Everything that was checked before calling it ready

| Check | Result |
|---|---|
| `sigma check`, the file | 0 errors, 0 condition errors, 0 issues |
| `sigma check`, all of `rules/cloud/azure/` | same, nothing else disturbed |
| JSON schema `v2.1.0`, the exact tag the CI pins | valid |
| yamllint rules from their own `.yamllint`, run by hand | clean, no pip in this venv |
| trailing spaces, CRLF, final newline, 4 space indent | clean |
| non-ASCII left in the file | **none**, which is the point |
| merge against upstream master | no conflict |
| merge against fukusuket's #5993 branch | **no conflict, verified by inspecting the merged file** |
| our own `audit_operations.py` | SHORTHAND gone, fragment correctly reported as a fragment |
| longest line added | 106 chars, shorter than two lines already in the file |

### Deliberately left out

- **Regression data.** The README says rules with `status: test` must point at an `info.yml` with a
  real event, and JSON samples are supported. **Zero cloud rules in the repo have any**, so this
  would be the first. We have the real event, but `golang_expr` is not installed here and there is no
  `json_checker` binary, so it cannot be executed locally. Offered in the PR body rather than shipped.
  Shipping a test we have not run is exactly the thing we said we would stop doing.
- **`Add service principal credentials`.** A real operation, confirmed live, and **no rule in the
  whole repository covers it**, checked across every `rules*` directory and #5993. That is its own
  rule, not a widening of this PR.
- **The `Create application` form.** Same reasoning. Real, 2 events, uncovered, out of scope here.

### Provenance, stated correctly in the PR

The hyphen is ours, commit `3153e89` of #6247, 2026-08-20. The slash joined value is **not** ours and
not the reviewer's: Swachchhanda's commit only added quotes, and it is in the rule as authored in
2022 by Morowczynski and Bercik. nasbench added the inline comment. The PR says so.

**Not opened.** PR body drafted, 4,134 characters, em dash scan clean.
