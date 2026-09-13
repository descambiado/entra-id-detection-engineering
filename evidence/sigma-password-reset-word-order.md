# `Password reset` is the wrong word order, so the rule cannot catch what its title says

**Finding date:** 2026-09-13
**Rule:** SigmaHQ `rules/cloud/azure/audit_logs/azure_user_password_change.yml`, title
*Password Reset By User Account*, description *"Detect when a user has reset their password"*
**Where:** PR **#5993** (fukusuket), commit `80861bc`, pushed 2026-09-13T00:45Z
**Status:** not reported yet.

## Why this is partly on us

This rule was changed **in response to our comment**. It previously carried an unconfigured
`|expand: '%UPN%'` placeholder, which we pointed out refuses to convert at all. fukusuket removed
the placeholder and simplified the condition:

```diff
-        properties.initiatedBy|contains|expand: '%UPN%'
-    filter:
-        properties.targetResources|contains|expand: '%UPN%'
         operationName|contains: 'Password reset'
-    condition: selection and filter
+    condition: selection
```

The simplification is right and the rule now converts. But it leaves `operationName|contains:
'Password reset'` as the only operation predicate, and that string is inherited from the 2022
original, where it sat on the non existent field `ActivityType`. Nobody has ever checked it, because
until now the rule was broken in a louder way.

## The defect

Entra names these operations **verb first**. The two that mean "a user reset their own password" are:

```
Reset password (self-service)
Change password (self-service)
```

Neither contains the substring `password reset`, in any case. The word order is reversed.

Of the 30 password bearing activities in Microsoft's audit activity reference, **6** contain
`password reset` case insensitively, and every one of them is a narrative or intermediate event,
not a completed password change:

| Activity | What it is |
|---|---|
| `Self-service password reset flow activity progress` | flow progress |
| `Admin started password reset` | started, not finished |
| `user started password reset` | started, not finished |
| `Blocked from self-service password reset` | blocked attempt |
| `Security info saved for self-service password reset` | registering security info |
| `User Password Reset` | B2C style naming |

The `category: 'UserManagement'` filter is **correct**, checked against the reference: all of the
above and both self-service operations are UserManagement. The category is not the problem.

## Microsoft's own detection does not use a `contains` on this string

`Azure-Sentinel/Detections/MultipleDataSources/MultiplePasswordresetsbyUser.yaml`, author
*Microsoft Security Research*, commits from `v-vdixit@microsoft.com` and CyberCX 2023 to 2024,
**no involvement of ours**, checked with `git log`:

```kql
let selfServicePasswordReset = dynamic(["Self-service password reset flow activity progress",
                                        "Change password (self-service)",
                                        "Reset password (self-service)"]);
let action = dynamic(["change", "changed", "reset"]);
let pWord  = dynamic(["password", "credentials"]);
AuditLogs
| where OperationName has_any (pWord) and OperationName has_any (action) and Result =~ "success"
| where OperationName !in (selfServicePasswordReset)
```

Two things worth reading twice. Microsoft matches **tokens in any order**, never the phrase, which
is exactly the trap this rule fell into. And the one activity the Sigma rule most plausibly does hit,
`Self-service password reset flow activity progress`, Microsoft explicitly **excludes as benign**,
with the comment: *this operation already implies the user has signed in successfully and therefore
the password reset is non malicious.*

So the rule misses every completed password reset and, where it matches at all, matches the event
Microsoft's own detection throws away.

## Proof level, stated honestly

**Not an executed test.** Our tenant has no password events in the retention window, and both routes
to generate one were unavailable: writing a password through Graph and bulk reading
`directoryAudits` were both refused. `contains 'Password reset'` returns 0 rows in our workspace,
but with no password events present that number proves nothing and is **not** offered as evidence.

What carries the finding is documentary, and it is positive rather than an argument from absence:
`Reset password (self-service)` and `Change password (self-service)` are **present** in two
independent Microsoft sources, and the rule's string matches neither. That does not depend on the
reference being complete, which it is not.

## Not claimed

- Not claimed that nothing at all matches. Something probably does, and it is the wrong thing.
- Case was considered and **dropped**. `Password reset` with a capital P appears in 0 of the 30, but
  the finding holds in any case, so raising it would only dilute it.
- Trap 5 run: no open SigmaHQ PR touches this file other than #5993 itself.

## Suggested wording, if reported

Follow Microsoft: `operationName|contains: 'password (self-service)'` catches both `Reset password
(self-service)` and `Change password (self-service)` and nothing else, which is exactly the rule's
stated intent.
