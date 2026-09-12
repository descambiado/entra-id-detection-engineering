#!/usr/bin/env python3
"""Audit Sigma azure signinlogs rules.

These rules do not select on operation names, so the two catalogue auditors have
nothing to say about them. They select on field names and on Entra sign-in result
codes, which are two different questions:

  fields   checked against the real SigninLogs columns, exported from the
           installed pySigma azuremonitor pipeline
  values   the ResultType codes, reported so a human can look them up. There is
           no offline catalogue of Entra error codes worth shipping, so this
           tool prints them rather than pretending to verify them.

Verdicts follow the same grading as the rest of the suite, and the same rule
applies: CASE is not a finding, because the kusto backend emits `=~`, and ABSENT
is a candidate that needs checking, not a result.

Two things this tool will flag that are NOT defects, both confirmed by hand on
2026-09-12, so read before believing the output:

  - `properties.message` and other Event Hub style names. One rule,
    azure_privileged_account_sigin_expected_controls.yml, uses `callerIpAddress`,
    `location`, `resultType` and `properties.deviceDetail.deviceId` together.
    That is the Event Hub envelope used consistently, not four mistakes.
  - The ten case-only differences. `resultType` vs `ResultType`, `userAgent` vs
    `UserAgent` and so on all resolve, because of `=~`.

Run:  py audit_signinlogs.py <path to sigma repo>
"""
import json
import pathlib
import sys
from collections import Counter

try:
    import yaml
except ImportError:
    sys.exit("pyyaml is required")

HERE = pathlib.Path(__file__).parent
SCHEMA = json.loads((HERE / "azure_schema.json").read_text(encoding="utf-8"))
COLS = set(SCHEMA["SigninLogs"])
COLS_LOWER = {c.lower(): c for c in COLS}

# Sigma conventions and Event Hub envelope names. Not columns, not defects.
CONVENTIONS = {"properties.message", "callerIpAddress"}


def root_of(field):
    """Return (root column candidate, name as written).

    The name as written keeps the properties. prefix, because the CONVENTIONS
    check has to see the original. Stripping first made properties.message
    arrive as 'message' and report ABSENT, which is the tool contradicting its
    own docstring.
    """
    written = field.split("|")[0]
    base = written[len("properties."):] if written.startswith("properties.") else written
    return base.split(".")[0], written


def main():
    repo = pathlib.Path(sys.argv[1] if len(sys.argv) > 1 else ".")
    field_rows, code_rows = [], []
    rules = 0

    for path in sorted(repo.glob("rules*/**/*.yml")):
        if "/azure/" not in path.as_posix():
            continue
        try:
            rule = yaml.safe_load(path.read_text(encoding="utf-8"))
        except Exception:
            continue
        if not rule:
            continue
        if ((rule.get("logsource") or {}).get("service") or "").lower() != "signinlogs":
            continue
        rules += 1
        for name, block in (rule.get("detection") or {}).items():
            if name == "condition":
                continue
            for b in (block if isinstance(block, list) else [block]):
                if not isinstance(b, dict):
                    continue
                for field, value in b.items():
                    root, base = root_of(field)
                    if base in CONVENTIONS:
                        field_rows.append((path.name, base, "CONVENTION", ""))
                    elif root in COLS:
                        field_rows.append((path.name, base, "EXACT", ""))
                    elif root.lower() in COLS_LOWER:
                        field_rows.append((path.name, base, "CASE", COLS_LOWER[root.lower()]))
                    else:
                        field_rows.append((path.name, base, "ABSENT", ""))
                    if root.lower() == "resulttype":
                        for v in (value if isinstance(value, list) else [value]):
                            code_rows.append((path.name, str(v)))

    seen = set()
    uniq = []
    for r in field_rows:
        if (r[1], r[2]) in seen:
            continue
        seen.add((r[1], r[2]))
        uniq.append(r)
    counts = Counter(r[2] for r in uniq)

    print(f"signinlogs rules       : {rules}")
    print(f"distinct field names   : {len(uniq)}   against {len(COLS)} real SigninLogs columns")
    for k in ("EXACT", "CONVENTION", "CASE", "ABSENT"):
        if counts.get(k):
            print(f"  {k:<11}: {counts[k]}")

    print("\nnot EXACT, in order of how much they matter:")
    for name, base, verdict, real in sorted(uniq, key=lambda r: {"ABSENT": 0, "CASE": 1, "CONVENTION": 2}.get(r[2], 3)):
        if verdict == "EXACT":
            continue
        tail = f"real column is {real}" if real else ""
        print(f"  [{verdict:<10}] {base:<40} {tail}")

    codes = sorted({c for _, c in code_rows}, key=lambda x: (len(x), x))
    print(f"\nResultType codes used  : {len(codes)}")
    print("  " + ", ".join(codes))
    print("  Look one up at https://login.microsoftonline.com/error?code=<code>")
    return 0


if __name__ == "__main__":
    sys.exit(main())
