#!/usr/bin/env python3
"""Work out which Log Analytics table each Sigma azure logsource actually targets.

Guessing this wrong is not a small mistake. Checking activitylogs rules against
the Entra audit activity list produced 128 false findings on 2026-09-08, because
Azure Activity Log operations look like MICROSOFT.NETWORK/APPLICATIONGATEWAYS/WRITE
and were never going to appear there.

So instead of assuming, infer it: collect every field name the rules of a service
use, then score all 698 exported table schemas by how many of those fields they
contain. The right table should win by a wide margin. If nothing wins clearly,
that service stays unmapped and its rules stay out of the audit.
"""
import json
import pathlib
import sys
from collections import Counter, defaultdict

try:
    import yaml
except ImportError:
    sys.exit("pyyaml is required")

HERE = pathlib.Path(__file__).parent
SCHEMA = json.loads((HERE / "azure_schema.json").read_text(encoding="utf-8"))

# Field name prefixes that are Sigma conventions rather than column names.
CONVENTION_PREFIXES = ("properties.",)


def base_of(field):
    b = field.split("|")[0]
    for p in CONVENTION_PREFIXES:
        if b.startswith(p):
            b = b[len(p):]
    return b.split(".")[0]


def main():
    repo = pathlib.Path(sys.argv[1] if len(sys.argv) > 1 else ".")
    by_service = defaultdict(Counter)
    rule_count = Counter()

    for path in repo.glob("rules*/**/*.yml"):
        if "/azure/" not in path.as_posix():
            continue
        try:
            rule = yaml.safe_load(path.read_text(encoding="utf-8"))
        except Exception:
            continue
        if not rule:
            continue
        svc = ((rule.get("logsource") or {}).get("service") or "?").lower()
        rule_count[svc] += 1
        det = rule.get("detection") or {}
        for name, block in det.items():
            if name == "condition":
                continue
            for b in (block if isinstance(block, list) else [block]):
                if isinstance(b, dict):
                    for f in b:
                        by_service[svc][base_of(f)] += 1

    lowered = {t: {c.lower() for c in cols} for t, cols in SCHEMA.items()}

    for svc in sorted(by_service, key=lambda s: -rule_count[s]):
        fields = by_service[svc]
        distinct = set(fields)
        print(f"\n=== service: {svc}  ({rule_count[svc]} rules, {len(distinct)} distinct fields) ===")
        scores = []
        for table, cols in lowered.items():
            hit = {f for f in distinct if f.lower() in cols}
            if hit:
                scores.append((len(hit) / len(distinct), len(hit), table, hit))
        scores.sort(reverse=True)
        if not scores:
            print("  no table contains any of these fields. LEAVE UNMAPPED.")
            continue
        best = scores[0]
        for cover, n, table, hit in scores[:3]:
            print(f"  {cover:5.0%}  {n:>2}/{len(distinct)}  {table}")
        missing = distinct - best[3]
        print(f"  -> best: {best[2]}")
        if missing:
            print(f"     fields it does NOT have: {sorted(missing)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
