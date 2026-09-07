#!/usr/bin/env python3
"""Audit public Sigma azure rules for detections that cannot fire.

Findings are graded by how certain they are, because "this does not match the
schema I happen to be thinking of" is a preference, not a finding:

  CERTAIN  the value can never occur, whatever the schema. Template
           placeholders left in the rule. Schema independent, so it survives
           every disagreement about representations.
  LIKELY   the field exists in none of the three representations of the event.
  WEAK     the field exists with different casing or nesting. Backend
           dependent. Reported, never claimed.

Three representations of the same event exist and a field name only means
something against one of them:

  graph         /auditLogs/directoryAudits    camelCase, no prefix
  loganalytics  the AuditLogs/SigninLogs...   PascalCase, real column names
  eventhub      diagnostic setting export     camelCase under properties.*

Column names come from azure_schema.json, exported from the installed pySigma
azuremonitor pipeline, not typed from documentation.

Run:  py audit_rules.py <path to sigma repo>
"""
import collections
import json
import pathlib
import re
import sys

try:
    import yaml
except ImportError:
    sys.exit("pyyaml is required:  py -m pip install pyyaml")

HERE = pathlib.Path(__file__).parent
SCHEMA = json.loads((HERE / "azure_schema.json").read_text(encoding="utf-8"))

# Sigma logsource service -> Log Analytics table. Only mappings that were
# checked against the exported schema. A service that is not here is skipped
# rather than guessed: a wrong table would manufacture findings.
SERVICE_TABLE = {
    "auditlogs": "AuditLogs",
    "signinlogs": "SigninLogs",
    "activitylogs": "AzureActivity",
    "riskdetection": "AADUserRiskEvents",
}

# Field names observed live in a real tenant through Graph.
GRAPH = {
    "activityDateTime", "activityDisplayName", "additionalDetails", "category",
    "correlationId", "id", "initiatedBy", "loggedByService", "operationType",
    "result", "resultReason", "targetResources", "app", "user", "ipAddress",
    "userPrincipalName", "displayName", "modifiedProperties", "oldValue",
    "newValue", "type", "userType", "homeTenantId", "homeTenantName", "key",
    "value", "groupType", "agentType",
}

# Established SigmaHQ conventions for these logsources. They resolve to no
# column and the pipeline's generic_mappings is empty, so they do not convert
# cleanly either, and they are still NOT findings: 23 of the 45 audit_logs
# rules use properties.message including one merged in September 2026 after
# maintainer review. That makes it a convention question for the project, not
# a broken rule. Calling it a defect would be the same assumption-driven
# overreach that got five PRs closed in May. Excluding it took the report from
# 27 rules to 8, which is the difference between a finding and noise.
CONVENTIONS = {"properties.message"}

# Values that are placeholders, not data.
PLACEHOLDERS = {
    "upn", "username", "user name", "userprincipalname", "<upn>", "example",
    "target", "displayname", "ipaddress", "<ip>", "changeme", "todo", "tbd",
    "yourvalue", "value", "string", "n/a",
}


def columns_for(service):
    table = SERVICE_TABLE.get((service or "").lower())
    return set(SCHEMA.get(table, [])) if table else None


def leaves(detection):
    for name, block in detection.items():
        if name == "condition":
            continue
        for b in (block if isinstance(block, list) else [block]):
            if isinstance(b, dict):
                for field, value in b.items():
                    yield name, field, value


def grade_field(field, cols):
    """Return (grade, why) or None when the field is fine."""
    base = field.split("|")[0]
    if base in CONVENTIONS:
        return None
    stripped = base[len("properties."):] if base.startswith("properties.") else base
    # accepted in any of the three representations
    if base in cols or stripped in cols or stripped in GRAPH or base in GRAPH:
        return None
    lower = {c.lower() for c in cols} | {g.lower() for g in GRAPH}
    if stripped.lower() in lower or stripped.split(".")[0].lower() in lower:
        return ("WEAK", "field exists but with different casing or nesting")
    return ("LIKELY", "field name appears in no known representation")


def audit(repo):
    root = pathlib.Path(repo)
    files = [p for p in root.glob("rules*/**/*.yml")
             if "/azure/" in p.as_posix()]
    findings = []
    skipped = collections.Counter()
    for path in sorted(files):
        try:
            rule = yaml.safe_load(path.read_text(encoding="utf-8"))
        except Exception as exc:
            findings.append((path.name, "PARSE", "", f"cannot parse: {exc}"))
            continue
        if not rule:
            continue
        service = (rule.get("logsource") or {}).get("service")
        detection = rule.get("detection") or {}
        cols = columns_for(service)

        condition = str(detection.get("condition", ""))
        if re.search(r"\band\s+filter\b", condition) and "not" not in condition:
            findings.append((
                path.name, "SMELL", "condition",
                f"a block named 'filter' is ANDed in, not negated: {condition!r}. "
                "Either it is a second selection with a misleading name, or the "
                "condition is wrong. Read the rule."))

        for block, field, value in leaves(detection):
            for v in (value if isinstance(value, list) else [value]):
                if isinstance(v, str) and v.strip().lower() in PLACEHOLDERS:
                    exact = "|" not in field
                    findings.append((
                        path.name, "CERTAIN", f"{block}.{field}",
                        f"value {v!r} is a template placeholder, not data"
                        + (". Exact match, so it can never be true."
                           if exact else
                           ". Substring match, so it can only match by coincidence.")))
            if cols is None:
                skipped[service] += 1
                continue
            graded = grade_field(field, cols)
            if graded:
                findings.append((path.name, graded[0], f"{block}.{field}", graded[1]))
    return files, findings, skipped


def main():
    repo = sys.argv[1] if len(sys.argv) > 1 else "."
    files, findings, skipped = audit(repo)
    order = {"PARSE": 0, "CERTAIN": 1, "LIKELY": 2, "SMELL": 3, "WEAK": 4}
    findings.sort(key=lambda x: (order.get(x[1], 9), x[0]))

    counts = collections.Counter(g for _, g, _, _ in findings)
    hard = {n for n, g, _, _ in findings if g in ("CERTAIN", "LIKELY")}
    print(f"azure rules audited : {len(files)}")
    print(f"rules with a CERTAIN or LIKELY finding : {len(hard)}")
    for grade in ("PARSE", "CERTAIN", "LIKELY", "SMELL", "WEAK"):
        if counts.get(grade):
            print(f"  {grade:<8}: {counts[grade]}")
    if skipped:
        print(f"  fields skipped, service has no verified table: {dict(skipped)}")

    current = None
    for name, grade, where, why in findings:
        if name != current:
            print(f"\n{name}")
            current = name
        print(f"  [{grade}] {where}")
        print(f"          {why}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
