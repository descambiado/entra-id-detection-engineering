#!/usr/bin/env python3
"""Check every operation name a Sigma azure rule selects on against the list
Microsoft actually publishes.

This exists because of an objection raised publicly by another practitioner:
generating events only validates the operations you thought to generate, so
most of the corpus stays assumption. That objection is correct for values that
have to be observed. It is NOT correct for operation names, because Microsoft
publishes the complete list of audit activities. A rule selecting on a string
that is not in that list cannot fire, and no event is needed to know it.

Verdicts:
  EXACT      the value is in Microsoft's list verbatim
  CASE       matches only when case is ignored. NOT A FINDING, verified
             2026-09-08: the pySigma kusto backend emits `=~`, which is case
             insensitive in KQL, so 'conditional access policy' does match
             'Conditional Access policy'. Confirmed by converting a rule and
             reading the operator, and separately by querying a live workspace
             where `== 'add member to group'` returns 0 and `=~` returns 1.
             Reported for completeness only. Six of these were nearly written
             up as findings before the check was run.
  WHITESPACE matches only after stripping, so the rule carries stray spacing
  DASH       matches only after normalising dash characters
  ABSENT     no match under any of the above.

IMPORTANT, learned the hard way on 2026-09-08 and the reason this docstring is
long: ABSENT IS A CANDIDATE, NOT A FINDING. Microsoft's published audit activity
reference is INCOMPLETE. `Add eligible member (permanent)` does not appear in it,
yet Microsoft's own Sentinel analytic rule UserAddedtoAdminRole.yaml queries
`OperationName in ("Add eligible member (permanent)", "Add eligible member
(eligible)", "Add member to role")`. So the operation almost certainly exists and
the reference simply does not list it.

Four rules were about to be written up as broken on ABSENT alone. Checking
Microsoft's own detection content first stopped that. Absence from the list
proves nothing on its own; presence in it proves the string is real.

An ABSENT result is promoted to a finding only by an executed test: generate the
event and show the rule's string returns nothing while the real one returns the
row. That is how `Add member from group` was confirmed, and it is the only one of
the five candidates that has been.

ABSENT is not automatically a bug. A partial value behind |contains is meant to
be a fragment, and a rule may target an operation Microsoft has not documented.
Both are called out separately rather than counted as findings.

Run:  py audit_operations.py <path to sigma repo>
"""
import json
import pathlib
import re
import sys
import unicodedata

try:
    import yaml
except ImportError:
    sys.exit("pyyaml is required")

HERE = pathlib.Path(__file__).parent
MS = json.loads((HERE / "ms_audit_activities.json").read_text(encoding="utf-8"))

# Fields that carry an operation name in one representation or another.
OP_FIELDS = {
    "properties.message", "operationname", "operationName", "activitydisplayname",
    "activityDisplayName", "activitytype", "activityType", "operationName",
}
DASHES = dict.fromkeys(map(ord, "‐‑‒–—―−"), "-")


def norm(s):
    return unicodedata.normalize("NFKC", s)


def classify(value, ms_exact, ms_lower, ms_strip, ms_dash):
    v = norm(value)
    if v in ms_exact:
        return "EXACT", None
    if v.lower() in ms_lower:
        return "CASE", ms_lower[v.lower()]
    if v.strip() in ms_strip:
        return "WHITESPACE", ms_strip[v.strip()]
    d = v.translate(DASHES).strip().lower()
    if d in ms_dash:
        return "DASH", ms_dash[d]
    return "ABSENT", None


def main():
    repo = pathlib.Path(sys.argv[1] if len(sys.argv) > 1 else ".")
    ms_exact = set(map(norm, MS))
    ms_lower = {norm(m).lower(): m for m in MS}
    ms_strip = {norm(m).strip(): m for m in MS}
    ms_dash = {norm(m).translate(DASHES).strip().lower(): m for m in MS}

    from collections import Counter
    skipped = Counter()
    results = []
    files = [p for p in repo.glob("rules*/**/*.yml") if "/azure/" in p.as_posix()]
    for path in sorted(files):
        try:
            rule = yaml.safe_load(path.read_text(encoding="utf-8"))
        except Exception:
            continue
        if not rule:
            continue
        # Microsoft's list covers Entra ID AUDIT activities only. Azure Activity
        # Log operations (MICROSOFT.NETWORK/... etc) and sign-in logs use entirely
        # different naming schemes, so checking them against this list is a
        # category error that manufactures findings. The first run of this script
        # produced 128 "ABSENT" results, most of them exactly that mistake.
        service = ((rule.get("logsource") or {}).get("service") or "").lower()
        if service != "auditlogs":
            skipped[service or "?"] += 1
            continue

        det = rule.get("detection") or {}
        for block, spec in det.items():
            if block == "condition":
                continue
            for b in (spec if isinstance(spec, list) else [spec]):
                if not isinstance(b, dict):
                    continue
                for field, value in b.items():
                    base, _, mods = field.partition("|")
                    if base.split(".")[-1].lower() not in {f.split(".")[-1].lower() for f in OP_FIELDS}:
                        continue
                    partial = any(m in mods for m in ("contains", "startswith", "endswith", "re"))
                    for v in (value if isinstance(value, list) else [value]):
                        if not isinstance(v, str):
                            continue
                        verdict, match = classify(v, ms_exact, ms_lower, ms_strip, ms_dash)
                        results.append((path.name, field, v, verdict, match, partial))

    order = {"ABSENT": 0, "DASH": 1, "WHITESPACE": 2, "CASE": 3, "EXACT": 4}
    results.sort(key=lambda r: (order[r[3]], r[0]))

    counts = Counter(r[3] for r in results)
    print(f"operation-name values checked : {len(results)}  (auditlogs rules only)")
    if skipped:
        print(f"  rules skipped, different log source and naming scheme: {dict(skipped)}")
    for k in ("EXACT", "CASE", "WHITESPACE", "DASH", "ABSENT"):
        if counts.get(k):
            print(f"  {k:<11}: {counts[k]}")
    print()
    for name, field, value, verdict, match, partial in results:
        if verdict == "EXACT":
            continue
        tag = " [partial match, expected to be a fragment]" if partial else ""
        print(f"[{verdict}] {name}")
        print(f"    rule has  : {value!r}{tag}")
        if match:
            print(f"    Microsoft : {match!r}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
