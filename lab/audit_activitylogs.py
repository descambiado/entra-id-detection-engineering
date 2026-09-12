#!/usr/bin/env python3
"""Audit Sigma azure activitylogs rules against Azure's own operation catalogue.

The Entra audit activity list does not apply to these rules and checking them
against it produced 128 false results once already. Azure Activity Log operations
are ARM resource provider operations, and Azure publishes them through the
management API, so `az provider operation show --namespace X` is the authoritative
list for this logsource.

Unlike Microsoft's Entra activity reference, which is demonstrably incomplete,
this catalogue is generated from the resource providers themselves. That makes an
ABSENT result here stronger than an ABSENT result there, but still not a finding
on its own: a provider can register an operation the catalogue lags on, and
`az provider operation show` only returns operations for providers registered in
the subscription it is run against.

Comparison is case insensitive on purpose. The rules use UPPERCASE, ARM publishes
mixed case, and the Sigma kusto backend emits `=~`, which is case insensitive in
KQL. Case differences here are cosmetic, unlike the value differences.

Run:  py audit_activitylogs.py <path to sigma repo>
"""
import pathlib
import sys
from collections import Counter

try:
    import yaml
except ImportError:
    sys.exit("pyyaml is required")

HERE = pathlib.Path(__file__).parent
ARM = [l.strip() for l in (HERE / "arm_operations.txt").read_text(encoding="utf-8").splitlines() if l.strip()]
ARM_LOWER = {a.lower(): a for a in ARM}
NAMESPACES = sorted({a.split("/")[0].lower() for a in ARM})


def main():
    repo = pathlib.Path(sys.argv[1] if len(sys.argv) > 1 else ".")
    rows = []
    for path in sorted(repo.glob("rules*/**/*.yml")):
        if "/azure/" not in path.as_posix():
            continue
        try:
            rule = yaml.safe_load(path.read_text(encoding="utf-8"))
        except Exception:
            continue
        if not rule:
            continue
        if ((rule.get("logsource") or {}).get("service") or "").lower() != "activitylogs":
            continue
        det = rule.get("detection") or {}
        for name, block in det.items():
            if name == "condition":
                continue
            for b in (block if isinstance(block, list) else [block]):
                if not isinstance(b, dict):
                    continue
                for field, value in b.items():
                    if not field.split("|")[0].lower().startswith("operationname"):
                        continue
                    mods = [m for m in field.split("|")[1:]]
                    for v in (value if isinstance(value, list) else [value]):
                        if not isinstance(v, str):
                            continue
                        rows.append((path.name, v, mods))

    findings = []
    counts = Counter()
    for fname, v, mods in rows:
        if mods:
            counts["FRAGMENT"] += 1
            continue
        low = v.lower()
        if low in ARM_LOWER:
            counts["EXACT"] += 1
            continue
        ns = low.split("/")[0]
        if ns not in NAMESPACES:
            counts["UNKNOWN_PROVIDER"] += 1
            findings.append((fname, v, "UNKNOWN_PROVIDER",
                             "provider not in the catalogue pulled for this audit"))
            continue
        # provider is known, so the catalogue should have had it
        near = [a for a in ARM_LOWER if a.startswith(ns + "/") and a.split("/")[-1] == low.split("/")[-1]]
        counts["ABSENT"] += 1
        findings.append((fname, v, "ABSENT",
                         f"{len(near)} operations in {ns} share the same final verb"))

    print(f"activitylogs operation values : {len(rows)}")
    for k in ("EXACT", "FRAGMENT", "ABSENT", "UNKNOWN_PROVIDER"):
        if counts.get(k):
            print(f"  {k:<17}: {counts[k]}")
    print(f"  ARM catalogue size: {len(ARM)} operations across {len(NAMESPACES)} providers")
    print()
    seen = None
    for fname, v, verdict, why in findings:
        if fname != seen:
            print(f"\n{fname}")
            seen = fname
        print(f"  [{verdict}] {v}")
        print(f"          {why}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
