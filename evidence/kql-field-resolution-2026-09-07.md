# Field resolution against a live Log Analytics workspace

**Captured 2026-09-07** from a real Microsoft Sentinel / Log Analytics workspace
(`law-detection-lab`, Spain Central) fed by Entra ID diagnostic settings.

## Why this file exists

Every claim below used to be an argument: "I read the schema and that column is not there."
An argument invites the reply "you are looking at the wrong representation". These are not
arguments. Kusto was asked to run the query and refused. The error text is quoted verbatim.

## Scope of the claim, stated before the results

This tests **one** representation: the Log Analytics `AuditLogs` and `SigninLogs` tables, which is
what Microsoft Sentinel queries. Sigma rules with `logsource: product: azure, service: auditlogs`
can also be converted for Event Hub or Graph shapes, where different names apply.

So the honest claim is not "this rule is broken everywhere". It is: **a user running these rules
against Microsoft Sentinel, which is the mainstream destination for this logsource, gets a query
the engine will not execute.**

## Results

| Rule | Field as written | Kusto response, verbatim |
|---|---|---|
| `azure_user_password_change.yml` | `Status` | `'where' operator: Failed to resolve column or scalar expression named 'Status'` |
| `azure_user_password_change.yml` | `Initiatedby` | `Failed to resolve column or scalar expression named 'Initiatedby'` |
| `azure_ad_account_created_deleted_nonapproved_user.yml` | `Initiatied.By` | `Failed to resolve expression 'Initiatied.By'` |
| `azure_app_end_user_consent.yml` | `ConsentContext.IsAdminConsent` | `Failed to resolve expression 'ConsentContext.IsAdminConsent'` |
| `azure_app_end_user_consent_blocked.yml` | `failure_status_reason` | `Failed to resolve column or scalar expression named 'failure_status_reason'` |
| `azure_legacy_authentication_protocols.yml` | `ActivityDetails` | `'where' operator: Failed to resolve column or scalar expression named 'ActivityDetails'` |
| `azure_legacy_authentication_protocols.yml` | `ClientApp` | `'where' operator: Failed to resolve column or scalar expression named 'ClientApp'` |
| `azure_legacy_authentication_protocols.yml` | `Username` | `'where' operator: Failed to resolve column or scalar expression named 'Username'` |

## Control, and it matters

The same field with the correct casing runs fine:

```
AuditLogs | where tostring(InitiatedBy) has 'UPN' | count      ->  valid query, 1 result row
```

`InitiatedBy` resolves. `Initiatedby` does not. That rules out "the whole table is missing" or "the
workspace is empty" as an explanation for the rejections above: the engine is resolving column names
and rejecting exactly the ones that are misspelled or absent.

## What this does NOT show

- It does **not** show these rules never fire for anyone. A different backend with a field-mapping
  pipeline could rewrite the names before they reach the engine.
- It does **not** cover `properties.message`, which 23 of the 45 audit_logs rules use, including one
  merged in September 2026 after maintainer review. That is a project convention question, not a
  defect, and it is deliberately excluded.
- `Status` in `SigninLogs` **is** a real column. The rejection above is specific to `AuditLogs`.

## Reproduce it

```bash
az login
bash lab/validate_kql.sh
```

---

Tool versions, environment and re-run instructions: [PROVENANCE.md](PROVENANCE.md)
