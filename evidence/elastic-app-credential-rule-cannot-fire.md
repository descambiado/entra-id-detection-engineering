# Elastic rule `Entra ID Application Credential Modified` cannot fire

**Finding date:** 2026-09-07
**Rule:** `rules/integrations/azure/persistence_entra_id_application_credential_modification.toml`
**Rule id:** created 2020-12-14, `maturity = "production"`, `updated_date = 2026/04/10`, not deprecated

## Claim

The rule's selection string uses U+002D HYPHEN-MINUS and no trailing space. The value that reaches
the field it queries carries U+2013 EN DASH and a trailing space. The field is mapped `keyword`, so
the comparison is exact. **The rule has never been able to match.**

## The chain, each link measured rather than assumed

**1. What the Entra diagnostic-settings export actually emits.**
Measured in a live Log Analytics workspace fed by that export:

```
OperationName : "Update application – Certificates and secrets management "
strlen        : 57
enDash        : True
hyphen        : False
endsWithSpace : True
```

Negative and positive control on the same rows:

```
AuditLogs | where OperationName == 'Update application - Certificates and secrets management'  ->  0
AuditLogs | where OperationName == strcat('Update application ','–',' Certificates and secrets management ')  ->  1
```

**2. Whether Elastic's ingest pipeline normalises it.** It does not. From
`packages/azure/data_stream/auditlogs/elasticsearch/ingest_pipeline/default.yml`, the only two
processors that touch the value are a `convert` to `event.action` and a `rename` to
`azure.auditlogs.operation_name`. Grepping all 410 lines for `trim`, `gsub`, `lowercase`,
`uppercase`, `replace` returns nothing. The string arrives as emitted.

**3. Whether the comparison is exact.** From `packages/azure/data_stream/auditlogs/fields`:

```yaml
    - name: operation_name
      type: keyword
```

`keyword` is not analysed, so the match is byte for byte. Had it been `text`, the standard analyser
would strip both dash characters and the query would match, and there would be no finding. This was
the check most likely to kill the finding, which is why it was done before writing anything.

**4. What the rule asks for.** Verified byte by byte in the TOML, U+002D at position 19:

```
azure.auditlogs.operation_name:"Update application - Certificates and secrets management"
```

Single clause. No alternative operation name that could rescue it.

## Why this matters

Adding credentials to an existing application registration is a core persistence and privilege
escalation technique: the credential lets an attacker authenticate as the application afterwards.
This is the rule meant to catch it.

## Related, and separate

The same operation exists in a `Create application` form,
`Create application – Certificates and secrets management `, which fires when an application is
created with credentials in a single Graph call. Confirmed with a real event carrying
`KeyDescription = ["[KeyIdentifier=...,KeyType=Password,...]"]`. **No rule in Elastic or SigmaHQ
covers that operation at all.** That is a coverage gap, independent of this string-matching bug.

## What is NOT claimed

- Nothing here applies to SigmaHQ's `azure_app_credential_added.yml`. That rule selects on
  `properties.message`, a different field in a convention this repo deliberately excludes from its
  audit, and a maintainer merged it knowingly.
- The workspace measurement proves what the export emits. It does not, on its own, prove what Elastic
  stores. Links 2 and 3 are what carry the claim across that gap, and both were read from Elastic's
  own package rather than inferred.

## Reproduce

```bash
az login
bash lab/decisive_dash_test.sh
```
