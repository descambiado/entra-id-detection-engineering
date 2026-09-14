# Detection lab

Tooling to validate detection rules against a live Entra ID tenant instead of
against documentation.

Standard library Python only, except `pyyaml` for reading Sigma rules. Nothing
to install if you already have it. Run everything with `py`.

---

## Why this exists

Every rule in this repo used to be written by reading Microsoft's documentation
and trusting that the operation names were right. Two of them were not, and
neither failed loudly, because a wrong detection rule does not throw an error.
It stays quiet for ever while you believe you are covered.

This directory turns three failure modes into mechanical checks.

**1. Ingestion lag makes you conclude the wrong thing.**
On 2026-08-20 a rule here was declared broken from what the portal showed at
04:36. The verdict was wrong: the missing records from the Authentication
Methods service landed around 05:05, and they proved the rule had been right all
along. `entra_lab.py watch` refuses to give a verdict until the event stream has
gone quiet for several consecutive polls.

**2. Wrong operation names die silently.**
`azure_ad_authentication_methods_policy_modified` selected on
`Update authentication methods policy` (that string does not exist, the real one
is `Authentication Methods Policy Update`) and filtered on category `Policy`
(real value `PolicyManagement`). Two independent fatal errors in one rule.
`match_rule.py` shows exactly which field failed and what the tenant emitted.

**3. Invented field names.**
A rule written for elastic/detection-rules used `azure.auditlogs.category`.
The real field is `azure.auditlogs.properties.category`. It was caught by
noticing it was the only file out of 136 using that spelling. `check_field.py`
does that check mechanically, so it does not depend on anyone remembering.

---

## One-time setup

You already have an app registration called `detection-lab-app` in the tenant.
It needs one permission added.

**1. Grant the permission**

Entra portal, `App registrations` > `detection-lab-app` > `API permissions`:

- `Add a permission` > `Microsoft Graph` > **Application permissions**
  (not Delegated: this runs without a signed-in user)
- Search `AuditLog.Read.All`, tick it, `Add permissions`
- Click **`Grant admin consent for <tenant>`**. Without this click the
  permission is listed but not active, and every call returns 403.

Optional, for the `signins` command: `Directory.Read.All`, same flow.

**2. Get the three values**

- Tenant ID and Client ID: on the app's `Overview` page.
- Client secret: `Certificates & secrets`. The existing one works if you still
  have the value. Secret values are shown once at creation and never again, so
  if you do not have it, create a new one.

**3. Put them in the environment**

Copy `.env.example` to `.env` and fill it in. `.env` is gitignored, and so is
`captures/`. Never paste a secret into a chat, a commit, or a screenshot.

PowerShell, for the current session:

```powershell
$env:ENTRA_TENANT_ID    = "..."
$env:ENTRA_CLIENT_ID    = "..."
$env:ENTRA_CLIENT_SECRET= "..."
```

To persist it for your user instead of retyping every time:

```powershell
[Environment]::SetEnvironmentVariable("ENTRA_TENANT_ID","...","User")
```

---

## The loop

```
1. py entra_lab.py watch
2. perform the action in the Entra portal
3. wait for the STABLE verdict, do not skip this
4. py match_rule.py <rule.yml> captures/<file>.capture.json
5. before opening a PR:
   py check_field.py <field> <path-to-target-repo-clone>
```

### entra_lab.py

```bash
py entra_lab.py watch                      # poll until quiet, then give a verdict
py entra_lab.py watch --timeout 3600       # for a service known to lag
py entra_lab.py recent --minutes 60        # quick snapshot, no verdict
py entra_lab.py signins --minutes 30       # sign-in logs
```

`watch` prints new events as they arrive and finishes with one of two verdicts:

- **STABLE**: the stream went quiet. Safe to draw conclusions.
- **NOT STABLE**: it never settled. Do not declare a rule dead from this data.

Captures are written to `captures/`, which is gitignored because audit records
contain tenant identifiers, user principal names, IP addresses and correlation
ids. Redact deliberately before using any of it in a write-up.

### match_rule.py

```bash
py match_rule.py ../sigma/persistence/azure_ad_sp_credentials_added.yml \
    captures/20260826T173000Z-watch.capture.json
```

When nothing fires it ranks the closest events and shows the diff:

```
FAIL  properties.message
      rule wants : ['Add service principal credentials']
      event has  : ['Update application - Certificates and secrets management']
```

**It gives three verdicts, never two.** This is the important design decision:

| Verdict | Meaning |
|---|---|
| `RULE FIRES` | every field matched |
| `rule does not fire` | at least one field demonstrably did not match |
| `CANNOT TELL` | something could not be evaluated honestly |

The third one is the point. Collapsing "I cannot tell" into "it does not fire"
is exactly how a working rule gets declared dead, which is the mistake this
whole directory exists to prevent. So a field the script cannot evaluate is
marked `SKIP` and counted neither way.

Known limits, stated rather than hidden. It evaluates a plain `selection` block
with `contains`, `startswith` and `endswith`. String comparison is case
insensitive, which follows the Sigma spec. These produce `CANNOT TELL` rather
than a fake answer:

- `re`, `base64`, `base64offset`, `cidr`, `gt`, `gte`, `lt`, `lte` modifiers
- a `condition` that is anything other than plain `selection`
- a `selection` that is not a mapping
- a field absent from `FIELD_MAP`, reported as `UNKNOWN_FIELD`

`UNKNOWN_FIELD` is worth reading carefully, because it has two very different
causes: a typo in the rule, or a gap in this script's field map. Find out which
before acting on it. Extend `FIELD_MAP` when it is the latter.

### check_field.py

```bash
py check_field.py azure.auditlogs.properties.category ../../detection-rules --ext .toml
```

Exits non-zero when a field has no precedent, or when exactly one file uses it,
because if that one file is yours then you invented the field.

---

## fixtures/

`portal-secret-and-policy.fixture.json` holds four synthetic audit records in
real Graph shape, reproducing what this tenant emitted on 2026-08-20: the portal
secret addition, the authentication methods policy update, and the pair of
records written for a single admin MFA registration.

That last pair is worth understanding. One admin action produces **two** records
with the same timestamp: `Admin registered security info` from Authentication
Methods, whose initiator is the real human, and `Update user` from Core
Directory, whose initiator is a Microsoft first party service principal. Any
rule that reads the actor from `initiatedBy.user.userPrincipalName` gets an empty
value on the second one and silently attributes nothing.

Every identifier is a placeholder with one deliberate exception:
`c1e0fa01-6ef3-49aa-89c9-59de350bfef5` is the real appId of the Microsoft first
party service principal `Azure Credential Configuration Endpoint Service`. It is
the same value in every tenant and it is public. It is kept real because
recognising it is the whole point of that record, and replacing it with zeros
would destroy the lesson.

Use the fixture to test changes to the tooling without touching the tenant:

```bash
py match_rule.py ../sigma/persistence/azure_ad_sp_credentials_added.yml \
    fixtures/portal-secret-and-policy.fixture.json
```

---

## Scope

This tool reads audit logs from one tenant: the author's own, used solely to
validate detection content. It performs no writes and touches no third party
system.

---

# The audit suite

Everything above validates one rule against events you captured. This part answers a different and
larger question: **of the detection rules published for Azure, how many cannot fire?**

You do not need a tenant for most of it. You need one only to promote an answer from "probably" to
"I ran it".

## The seven ways this method lies to you

Read this section before the tool list. Every item below produced a wrong answer here first, and
each one would have been published if it had not been checked.

**1. A field that is a project convention, not a column.** The first run of `audit_rules.py` reported
27 broken rules in `rules/cloud/azure/audit_logs`. Twenty-three of them were `properties.message`,
which resolves to no column anywhere and which 23 of the 45 rules use, including one merged after
maintainer review. It is how the project writes that logsource. Excluding it took the report from 27
to 8. **A value shared by half the corpus is a convention. Treat it as one.**

**2. Checking rules against the wrong catalogue.** The first run of `audit_operations.py` reported
128 absent operation names. Most were `activitylogs` rules, whose operations look like
`MICROSOFT.NETWORK/APPLICATIONGATEWAYS/WRITE` and were never going to appear in a list of Entra audit
activities. Restricting to `service: auditlogs` took it from 128 to 13. `infer_tables.py` exists so
the mapping is derived from the rules' own field names rather than assumed.

**3. Case differences that do not matter.** Six rules spell `conditional access policy` where
Microsoft writes `Conditional Access policy`. KQL `==` is case sensitive, so this looks fatal. The
pySigma kusto backend emits `=~`, which is not. Verified by converting a rule and reading the
operator, and again against a live workspace where `== 'add member to group'` returns 0 rows and
`=~` returns 1. **Not findings.**

**4. The vendor's own list is incomplete, and this is the worst one.** Four rules looked broken
because their operation names are absent from the 907 activities Microsoft publishes. Then Microsoft's
own Sentinel analytic rule `UserAddedtoAdminRole.yaml` turned out to query two of those exact strings.
The list is missing real operations, so **absence from it proves nothing**. It went from four findings
to one, and the one that survived did so because it had a captured event behind it, not a missing
entry.

The rule that falls out of all four: **ABSENT is a candidate. Only an executed test makes it a
finding.**

**And a fifth, added 2026-09-12, which is about process rather than the tools.** The one defect this
audit confirmed with an executed test turned out to be already fixed in an open PR that had been
waiting since May. The diff of that PR had been read three times that week and never searched for the
file name. **Before writing up any finding, grep the open PRs of that repository for the file.** An
independent confirmation of someone else's known bug is a useful comment on their PR. It is not your
finding. Generate the event, show the rule's value returns nothing where the real value returns the
row, and keep both queries.

**And a sixth, added 2026-09-13, which is the expensive one, because it is about our own merged
work.** SigmaHQ #6247 is ours and it is merged. It changed
`Update application – Certificates and secrets management` to the same string with U+002D, on two
stated grounds. Both were checked today and neither holds.

The first was *"Microsoft's own Entra ID solution uses U+002D"*. Microsoft's two analytic rules
match like this:

```kql
| where OperationName has_any ("Add service principal", "Certificates and secrets management")
  // captures ... "Update application - Certificates and secrets management" events
```

The hyphen is in the `//` comment. **The predicate deliberately matches a fragment with no dash in
it.** The citation read the comment as if it were the query.

The second was *"Elastic's rule agrees"*. Five days later we filed elastic/detection-rules #6749
arguing that exact Elastic value is a defect because the hyphen cannot match. **We cited as
corroboration the very string we then went on to call a bug.**

Against live data both values in that merged rule now return 0, while Microsoft's fragment returns 7.

Three habits fall out of it, and they are the ones worth keeping:

- **Cite the predicate, never the comment.** A `//` line next to a query is documentation, and
  documentation is the least reliable representation of all. The measured field is the claim.
- **Grep your own record before citing anyone.** The contradiction was two of our own PRs, five days
  apart, both public, both still open or merged. Anyone reading both would find it before we did.
- **Prefer the value with no disputed character in it.** Where a fragment exists that sidesteps the
  question entirely, take it. Microsoft did, and their query still works. Ours stopped working.

Mechanised where possible: `audit_operations.py` now has a `SHORTHAND` verdict for values that are
two real operation names joined into one, which caught `Update Service principal/Update Application`
in that same rule and `Request Approved/Denied` in another, and an ABSENT hint that offers real
activities using the same words in a different order, which caught `Password reset` against
`Reset password (self-service)`.

**And a seventh, added 2026-09-14, which is about verification checking itself.** A captured event
was being prepared for publication. It went through three passes:

1. A hand written substitution said **no leaks**. It had replaced a GUID before replacing the longer
   string that contained it, so a record id kept its internal shard and sequence. The check only
   searched for the full original strings, and the full string no longer existed.
2. A proper module was written with a `leaks()` function that checks **shapes** rather than a list,
   which is strictly better. It reported clean. Its own test then found a real shard quoted in its
   own docstring, in a file destined for a public repo.
3. An **independent sweep**, which simply searched the files for the real values known from the
   session, found two more: the exact Windows build inside a `User-Agent`, and a credential name
   spliced into a flat `KeyIdentifier=...,DisplayName=...` blob where no walk over JSON keys reaches.

Three passes, three different misses, each found only by a check built differently from the one
before. The rule that falls out of it:

**A tool cannot verify itself past its own blind spot.** Shape based checking finds what no list
anticipated, and value based checking finds what no shape anticipated. Publishing needs both, run
separately, and the second must not be written by looking at the first.

The practical form of it here: `sanitize.py` redacts and self checks, and a separate sweep greps the
staged files for the real identifiers taken from the live environment. Nothing is published on the
strength of the redactor's own opinion of itself.

## Freezing the evidence before the lab expires

`freeze_evidence.py` re-runs every claim in `evidence/` against the live workspace and records the
result. It exists because the lab is temporary: the Azure credit ends 2026-09-19 and retention is 30
days from 2026-09-07, so every sentence that reads "returns N rows" stops being checkable soon after.

Each claim is declared with the query that produced it and the count it should give, so running it
proves the claims still hold, and running it after the lab dies fails honestly instead of pretending.
The supporting events are frozen alongside, sanitized, because a count with no record under it is
just a number. **11 of 11 claims held on 2026-09-14.**

One claim is deliberately **not** in that table. `contains 'Password reset'` returns zero, but the
tenant holds no password events at all, so that zero measures nothing. Putting it in a file called
frozen evidence would dress up an absence as an executed test.

## Tools

| Tool | Question it answers | Needs a tenant |
|---|---|---|
| `infer_tables.py` | which Log Analytics table does this Sigma logsource target | no |
| `audit_rules.py` | do these rules reference fields that exist, graded by certainty | no |
| `audit_operations.py` | do these operation names exist in Entra's catalogue | no |
| `audit_activitylogs.py` | do these operation names exist in Azure's ARM catalogue | no |
| `audit_elastic_ops.py` | same question against elastic/detection-rules | no |
| `audit_signinlogs.py` | do these field names exist, and which result codes are used | no |
| `validate_kql.sh` | does the engine accept these fields at all | yes |
| `decisive_dash_test.sh` | what characters does the export actually emit | yes |
| `match_rule.py` | does this rule fire against a captured event | events only |
| `test_match_rule.py` | does the matcher still behave, 10 regression tests | no |
| `test_auditors.py` | are the four traps above still guarded, 22 regression tests | no |

## Running the tests

```bash
py -m unittest discover -s lab -p "test_*.py"    # 32 tests
```

Each of the four traps above is a test rather than only a paragraph. A trap
written down in a README comes back; a trap with a failing test does not. The
reference-data tests exist for a specific failure mode: if a catalogue silently
empties or truncates, every verdict flips to ABSENT at once and the report looks
like a jackpot instead of a bug.

Writing these caught a wrong assumption about this code, which is the point.
`properties.message` is excluded by `audit_rules.py`, which checks field names,
and is an accepted *input* to `audit_operations.py`, which checks the values
behind an operation-name field. Asserting it in the wrong module failed, and the
distinction is now spelled out in a test.

## Reference data, and where it came from

| File | Contents | Source |
|---|---|---|
| `ms_audit_activities.json` | 907 Entra audit activity names | Microsoft's audit activity reference. The raw page is kept beside it as `.raw.txt` so the extraction can be rechecked rather than trusted |
| `arm_operations.txt` | 2045 ARM operations | `az provider operation show`, pulled live for the 8 providers the rules reference |
| `azure_schema.json` | 698 Log Analytics table schemas | the installed pySigma azuremonitor pipeline, not typed from documentation |

**Both catalogues are known incomplete.** `Add eligible member (permanent)` is missing from the Entra
list. `Microsoft.Authorization/elevateAccess/action` is missing from the ARM one, almost certainly
because that command returns subscription-scope operations and this is tenant-scope. Neither absence
is evidence.

## What the suite found, and what it did not

**The corpus is closed.** All **105** Azure rules in SigmaHQ that an audit can say anything about,
plus all **136** rule files in elastic/detection-rules:

| Service | Rules | Status |
|---|---|---|
| `auditlogs` | 46 | audited, one confirmed finding and three open candidates |
| `activitylogs` | 35 | audited, **clean**, 98 of 115 operation values exact and both outliers explained |
| `signinlogs` | 24 | audited, **clean**, 3 absent field names all in one rule already being fixed upstream |
| `riskdetection` | 19 | **out of scope**, selects on `riskEventType`, no operation names or column-level fields to check |
| `pim` | 7 | out of scope, same reason |

That is 131 rules: 105 audited, 26 with nothing an audit of this kind can say. What came out:

- **Confirmed with an executed test:** one, `Add member from group`, an operation Entra does not emit.
  **Already being fixed by someone else.** SigmaHQ PR #5993 has corrected it since 2026-05-09 and
  this audit did not check before writing it up. See the correction at the top of
  `../evidence/sigma-add-member-from-group.md`.
- **Sent as fixes with evidence:** three, two merged or under review in SigmaHQ and one in Elastic.
- **Open candidates, not claimed:** three, listed in `../evidence/CANDIDATES-not-confirmed.md` with
  what would settle each.
- **Discarded after checking:** four sets, described above.

`activitylogs` came back **completely clean**, 98 of 115 operation values exact and both outliers
explained. `riskdetection` and `pim` are out of scope rather than unchecked: every one of their rules
selects on `riskEventType` and none uses an operation name.

Zero findings in a folder is a result worth publishing. It bounds the problem instead of leaving it
open.

## Honest limits

- This checks whether a rule **can** match. It says nothing about whether the logic is good, whether
  the detection is worth having, or whether it would be noisy.
- It only reaches rules that select on field names and operation names. Rules built on thresholds,
  correlation or aggregation are outside it.
- Field resolution is checked against the Log Analytics representation, which is what Microsoft
  Sentinel queries. A rule targeting a different backend may resolve differently.
- The objection that this does not answer, raised publicly by another practitioner and still
  standing: generating events only validates the operations you thought to generate. The catalogue
  checks close part of that gap because they scale to the whole corpus, but a field that exists and
  holds a value spelled differently still needs a real event, and that is where the interesting bugs
  live.
