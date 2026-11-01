# SigmaHQ has zero coverage for `Add service principal credentials`

> **CORRECTION, 2026-10-26.** "Zero coverage" was imprecise: it meant zero in **merged** rules,
> which is true, but an open PR already exists. **#6142** (lmaotrip, open since 2026-07-15) adds
> this exact rule with its own real captured evidence. The draft rule written from this finding
> (`azure_service_principal_credentials_added.yml`) was withdrawn once this was found, checking
> open PRs before writing up a finding, which should have happened before writing the draft rather
> than after. No PR of our own opened for this gap.

> **UPDATE, 2026-10-24, same day.** The rule drafted from this finding originally used a plain
> hyphen for the portal-path operation name. The real value uses an en dash (U+2013) and a
> trailing space, not a hyphen, confirmed by generating and capturing a real event through the
> Entra admin portal, not just corroborated from the older fixture below. A rule with the hyphen
> would never have fired for the most common path. Caught before anything was pushed, by this
> repo's own `lab/match_rule.py` docstring, which already documented the two-path problem. The
> Windows shell used for this session silently mangles non-ASCII terminal output in several
> different ways (cp1252 round-tripping, double-encoding through a stdin pipe); the eventual fix
> was done by comparing raw UTF-8 bytes read directly from the saved JSON files, never by trusting
> what the terminal printed. See the rule file and its commit message for the full account.

**Finding date:** 2026-10-24
**Scope:** `rules/cloud/azure/audit_logs/` in SigmaHQ, checked against the live tenant and against
Azure-Sentinel's own content for the same activity.

## Gap

SigmaHQ has no rule, of any kind, that selects on the Entra audit activity
`Add service principal credentials`. A repo-wide grep for the exact string and for
`service principal credential` under `rules/cloud/azure/` returns nothing.

This is not a broken rule like the other files in this directory. It is an absence, and absence
needs a different kind of evidence than a wrong value does: a real, executed event, captured against
the live schema, proving both that the activity exists exactly as named and that nothing in the repo
matches it.

## The real event

Generated against the lab tenant (name withheld), 2026-10-24, via a disposable
app registration created, credentialed and deleted in the same session (`lab-test-cred-addition-*`,
cleaned up immediately after capture, nothing left behind):

```json
{
  "activityDateTime": "2026-10-24T11:12:42.7038068Z",
  "activityDisplayName": "Add service principal credentials",
  "category": "ApplicationManagement",
  "operationType": "Update",
  "result": "success",
  "loggedByService": "Core Directory",
  "targetResources": [
    {
      "type": "ServicePrincipal",
      "modifiedProperties": [
        {
          "displayName": "KeyDescription",
          "newValue": "[\"[KeyIdentifier=...,KeyType=Password,KeyUsage=Verify,DisplayName=lab-test-cred]\"]",
          "oldValue": "[]"
        }
      ]
    }
  ]
}
```

Captured via Graph `auditLogs/directoryAudits`, which is the same source Log Analytics ingests
`AuditLogs` from. `category` and `activityDisplayName` are the two fields every existing SigmaHQ
Azure rule keys its detection on (see `azure_owner_added_to_service_principal.yml` for the sibling
rule, same shape, already in the repo). This event confirms both spellings exactly: no dash variant,
no case difference, nothing to trip on.

## What already exists elsewhere, and why that is interesting

Azure-Sentinel is not blind to this activity. Three of its hunting queries already key on service
principal credential addition, all built around actor rarity rather than raw presence:

- `ServicePrincipalCredentialAdditionByRareActor.yaml`
- `ServicePrincipalCredentialAdditionByNonHistoricalActor.yaml`
- `FreshRoleGrantedActorSpCredentialAdded.yaml`

So the detection logic for this activity is proven and already lives in KQL. SigmaHQ, the
vendor-neutral layer meant to carry that same logic to any backend, has nothing: not the rarity
version, not even the plain presence version a new SOC would reach for first.

## What this is, and what it is not

**This is:** a confirmed, executed, zero-ambiguity coverage gap, the kind SigmaHQ accepts PRs for
every week.

**This is not:** a finding about a bug, and not yet a rule. A raw "any addition" rule will be noisy
in any tenant doing routine certificate rotation or CI credential refresh. The Azure-Sentinel rules
above solve that with a rarity window, which is exactly the right next step before this becomes a
SigmaHQ PR: either port the rare-actor logic (keeping SigmaHQ's own documented false-positive
discipline), or ship a plain presence rule explicitly scoped and labeled `experimental` with the
rotation false positive written into the rule's own `falsepositives` field, which is how the rest of
this repo's sibling rules handle the same tradeoff.

**Not yet done:** writing the rule itself. That is a deliberate next step, not an oversight, left for
a session with time to get the false-positive handling right rather than rushing it.

Tool versions and environment: [PROVENANCE.md](PROVENANCE.md).
