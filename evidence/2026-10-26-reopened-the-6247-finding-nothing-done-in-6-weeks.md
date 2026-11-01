# The real finding today isn't new: it's that the 2026-09-13 finding was never acted on

**This is not a new technical discovery. It is a status check on an old one, and the status is bad.**

## What was already found, six weeks ago

Commit `8e102ad`, 2026-09-13, `evidence/sigma-6247-reversed-a-correct-dash.md` and
`evidence/sigma-password-reset-word-order.md`, already in this repo:

1. **Our own merged SigmaHQ PR #6247 made `azure_app_credential_added.yml` worse, not better.**
   The rule now selects `'Update application - Certificates and secrets management'` (plain hyphen),
   measured against a live workspace on 2026-09-13 to return **0 rows**. The real value, en dash and
   trailing space, returns 1 row. Confirmed independently, again, today (2026-10-26), same result.
2. **The rule's second value, `'Update Service principal/Update Application'`, has always been
   broken.** It is two operation names joined with a slash into one string. No real
   `OperationName` has ever contained a literal slash between two activity names. This needs no
   event to disprove, it is a syntax defect.
3. **A related rule, `azure_user_password_change.yml`, has its words backwards.** It selects
   `contains 'Password reset'`; Entra's real activities are `Reset password (self-service)` and
   `Change password (self-service)`, verb first. Documented against two independent Microsoft
   sources, including Microsoft's own `MultiplePasswordresetsbyUser.yaml`, which explicitly excludes
   the one event the Sigma rule might hit as benign.
4. The September finding closed with: *"Not reported anywhere. Reversing our own merged PR is
   David's call."*

## What's changed since, checked live today, not assumed

- **`azure_app_credential_added.yml` on SigmaHQ `master`: byte-for-byte identical** to what the
  September commit describes. Six weeks, zero changes, by anyone.
- **The blast radius grew.** September counted 5 of our own Azure-Sentinel hunting queries carrying
  the broken hyphen value. Today's grep finds **11 files carrying it, 7 of them ours**:
  `FreshRoleGrantedActorSpCredentialAdded.yaml`, `PasswordResetThenPrivilegedOperation.yaml`,
  `ServicePrincipalCredentialAdditionByNonHistoricalActor.yaml`,
  `ServicePrincipalCredentialAdditionByRareActor.yaml`, `GuestAccountPrivilegedOperation.yaml`,
  `PrivilegedAccountLegacyAuthSignIn.yaml`, `SignInFromNewCountryWithSensitiveOperation.yaml`. The
  other 4 belong to other contributors (Or Shemesh x3, Pete Bryan x1) who independently carry the
  same value, likely from the same ultimate source rather than from copying us.
- **`azure_user_password_change.yml`: not checked again today**, no reason to expect it changed
  given the sibling file didn't move either.

## Why this matters more than any new rule written this session

A rule sitting broken and undiscovered costs nothing extra by the day. A rule **known broken and
left alone costs more every week**, because more content gets built on top of the same wrong value
(exactly what happened here: 5 files became 7) and because every day it stays live, SOCs running it
believe they are covered. This is the same pattern as the #14311 finding from two days ago, at a
larger scale and with a longer clock: not a one-off, a recurring failure mode in how findings here
turn into action.

## What's actually pending, concretely

1. Whether to revert or fix-forward `azure_app_credential_added.yml` upstream (not our rule to
   revert unilaterally; comment or PR, David's channel to choose).
2. Whether to fix the 7 own Azure-Sentinel hunting queries that carry the stale hyphen value, likely
   as one consolidated PR rather than seven.
3. Whether `azure_user_password_change.yml` gets reported, given the proof there is documentary
   only (explicitly, honestly, not executed).
4. Whether any of this changes how the newly-drafted pack from this session (service principal
   credentials, cross-tenant access) should reference or build on this older material, since the
   `azure_service_principal_credentials_added.yml` rule written today already covers the correct
   dash value as its own separate, new rule, independent of whether the older
   `azure_app_credential_added.yml` ever gets fixed.

Nothing opened, nothing commented, nothing reverted. This file only restates and re-verifies what
already existed, so the decision in front of David is accurate today, not six weeks stale.
