#!/usr/bin/env python3
"""Audit elastic/detection-rules azure rules the same way as the Sigma ones.

Same method, same limits. Read the operation names each rule selects on and
compare them against the 907 activity names Microsoft publishes.

The limit is identical and worth repeating because it already bit once: that
published list is INCOMPLETE. `Add eligible member (permanent)` is missing from
it while Microsoft's own Sentinel content queries the string. So ABSENT is a
candidate, never a finding. Promotion requires an executed test.

`azure.auditlogs.operation_name` is mapped `keyword` in the integration package
and the ingest pipeline does not normalise it, both checked on 2026-09-08, so the
comparison Elastic performs is exact, byte for byte. That is what makes a
character-level difference matter here rather than being cosmetic.

Run:  py audit_elastic_ops.py <path to detection-rules repo>
"""
import json
import pathlib
import re
import sys
import unicodedata
from collections import Counter

HERE = pathlib.Path(__file__).parent
MS = json.loads((HERE / "ms_audit_activities.json").read_text(encoding="utf-8"))
DASHES = dict.fromkeys(map(ord, "‐‑‒–—―−"), "-")

FIELD = "azure.auditlogs.operation_name"


def norm(s):
    return unicodedata.normalize("NFKC", s)


def classify(v, exact, lower, strip, dash):
    x = norm(v)
    if x in exact:
        return "EXACT", None
    if x.lower() in lower:
        return "CASE", lower[x.lower()]
    if x.strip() in strip:
        return "WHITESPACE", strip[x.strip()]
    d = x.translate(DASHES).strip().lower()
    if d in dash:
        return "DASH", dash[d]
    return "ABSENT", None


def values_in(query):
    """Pull the quoted values attached to the operation_name field.

    Handles both `field:"one"` and `field:("one" or "two")`.
    """
    out = []
    for m in re.finditer(re.escape(FIELD) + r"\s*:\s*(\(([^)]*)\)|\"([^\"]*)\")", query, re.S):
        blob = m.group(2) if m.group(2) is not None else m.group(3)
        out.extend(re.findall(r'"([^"]+)"', blob) or ([blob] if m.group(3) else []))
    return out


def main():
    repo = pathlib.Path(sys.argv[1] if len(sys.argv) > 1 else ".")
    exact = set(map(norm, MS))
    lower = {norm(m).lower(): m for m in MS}
    strip = {norm(m).strip(): m for m in MS}
    dash = {norm(m).translate(DASHES).strip().lower(): m for m in MS}

    results = []
    files = sorted((repo / "rules/integrations/azure").glob("*.toml"))
    for path in files:
        text = path.read_text(encoding="utf-8")
        if FIELD not in text:
            continue
        for v in values_in(text):
            if not v.strip():
                continue
            verdict, match = classify(v, exact, lower, strip, dash)
            results.append((path.name, v, verdict, match))

    order = {"ABSENT": 0, "DASH": 1, "WHITESPACE": 2, "CASE": 3, "EXACT": 4}
    results.sort(key=lambda r: (order[r[2]], r[0]))
    counts = Counter(r[2] for r in results)

    print(f"azure rule files            : {len(files)}")
    print(f"operation-name values found : {len(results)}")
    for k in ("EXACT", "CASE", "WHITESPACE", "DASH", "ABSENT"):
        if counts.get(k):
            print(f"  {k:<11}: {counts[k]}")
    print()
    for name, v, verdict, match in results:
        if verdict == "EXACT":
            continue
        print(f"[{verdict}] {name}")
        print(f"    rule has  : {v!r}")
        if match:
            print(f"    Microsoft : {match!r}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
