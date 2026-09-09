# Provenance

Every claim in this directory was produced with the versions below, against the tenant and workspace
below. Recorded because a finding you cannot re-run is not a finding, it is an anecdote, and this
file was created on 2026-09-09 after noticing the evidence files did not carry any of it.

## Tooling

| Tool | Version |
|---|---|
| azure-cli | 2.89.1 |
| az `log-analytics` extension | 1.0.0b1 |
| Python | 3.12.10 |
| pySigma | 1.5.0 |
| pySigma-backend-kusto | 1.0.1 |
| sigma-cli | 3.1.0 |
| PyYAML | 6.0.3 |

## Environment

| | |
|---|---|
| Log Analytics workspace | `law-detection-lab`, Spain Central, 30 day retention, 0.5 GB/day cap |
| Fed by | Entra ID diagnostic settings, `AuditLogs` + `SignInLogs` + non-interactive + service principal |
| Diagnostic setting created | 2026-09-07 14:16Z. **No row exists before that moment** |
| First row observed | 2026-09-07 15:23Z, 67 minutes later, against the 15 minutes Microsoft documents |
| Entra licence | Microsoft Entra ID P2 trial, activated 2026-08-23, 31 days |

## Reference data

`lab/ms_audit_activities.json`, 907 activity names, extracted from Microsoft's audit activity
reference. The raw page as fetched is kept alongside it as `ms_audit_activities.raw.txt` so the
extraction can be re-checked rather than trusted.

**Known incomplete.** `Add eligible member (permanent)` is absent from it while Microsoft's own
Sentinel analytic rule `UserAddedtoAdminRole.yaml` queries that exact string. Absence from this list
is therefore a candidate signal only, never a finding. See `lab/audit_operations.py`.

## Re-running

```bash
az login
bash lab/validate_kql.sh          # field resolution against the live engine
bash lab/decisive_dash_test.sh    # what the export emits for the dashed operation names
py  lab/audit_operations.py <path to sigma repo>
py  lab/audit_rules.py       <path to sigma repo>
py  lab/test_match_rule.py        # 10 regression tests for the matcher
```

## What cannot be re-run, and is marked as such

The captured events themselves. Log Analytics retention is 30 days from 2026-09-07, and the test
objects that generated them were deleted afterwards to keep the tenant clean. Where a claim rests on
a specific event, the event's shape is quoted verbatim in the relevant evidence file rather than
left as a reference to a row that will expire.
