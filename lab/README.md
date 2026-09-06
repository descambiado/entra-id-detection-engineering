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
