#!/usr/bin/env python3
"""Audit public Sigma azure/auditlogs rules for detections that cannot fire.

Three representations of the same Entra audit event exist, and a field name is
only meaningful against one of them:

  graph       /auditLogs/directoryAudits   camelCase, no prefix
  loganalytics  AuditLogs table            PascalCase
  eventhub    diagnostic setting export    camelCase under properties.*

A rule is only reported as broken when the finding survives ALL THREE. That is
the whole point: "it does not match the schema I happen to be thinking of" is
not a finding, it is a preference. Findings are graded:

  CERTAIN   the value can never occur, whatever the schema.
            Template placeholders left in the rule. Schema independent.
  LIKELY    the field name exists in no representation.
  WEAK      the field exists but with different casing or nesting.
            Depends on backend normalisation. Reported, never claimed.

Run:  py audit_rules.py <path to sigma repo>
"""
import collections
import json
import pathlib
import sys

try:
    import yaml
except ImportError:
    sys.exit("pyyaml is required:  py -m pip install pyyaml")

# Observed live in a real tenant, not copied from documentation.
GRAPH = {
    "activityDateTime", "activityDisplayName", "additionalDetails", "category",
    "correlationId", "id", "initiatedBy", "loggedByService", "operationType",
    "result", "resultReason", "targetResources", "app", "user", "ipAddress",
    "userPrincipalName", "displayName", "modifiedProperties", "oldValue",
    "newValue", "type", "userType", "homeTenantId", "homeTenantName", "key",
    "value", "groupType", "agentType",
}
# Log Analytics AuditLogs columns, read out of the installed pySigma
# azuremonitor pipeline rather than typed from documentation.
LOGANALYTICS = set(json.loads(
    (pathlib.Path(__file__).parent / "auditlogs_schema.json").read_text(encoding="utf-8")))
# Event Hub shape: the graph names, reachable under properties.*. Only names
# actually observed in a live event count, so properties.<anything invented>
# is not blessed by this set.
EVENTHUB = {"operationName"} | {f"properties.{f}" for f in GRAPH} | GRAPH

# Established SigmaHQ conventions for this logsource. They do not resolve to a
# column in any of the three representations, and the installed azuremonitor
# pipeline has an empty generic_mappings, so they do not convert cleanly either.
# They are still NOT findings. 23 of the 45 rules use properties.message,
# including one merged in September 2026 after maintainer review, so the
# maintainers treat it as correct and the question is a convention question for
# the project, not a broken rule. Calling it a defect would be exactly the
# assumption-driven overreach that got five PRs closed in May.
CONVENTIONS = {"properties.message"}

# Values that are placeholders, not data. A rule carrying one cannot fire.
PLACEHOLDERS = {
    "upn", "username", "user name", "userprincipalname", "<upn>", "example",
    "target", "displayname", "ipaddress", "<ip>", "changeme", "todo", "tbd",
    "yourvalue", "value", "string", "n/a",
}


def leaf_fields(detection):
    """Yield (field, value) for every leaf in every selection block."""
    for name, block in detection.items():
        if name == "condition":
            continue
        blocks = block if isinstance(block, list) else [block]
        for b in blocks:
            if not isinstance(b, dict):
                continue
            for field, value in b.items():
                yield name, field, value


def base_of(field):
    return field.split("|")[0]


def known_anywhere(field):
    b = base_of(field)
    return b in GRAPH or b in LOGANALYTICS or b in EVENTHUB


def known_case_insensitively(field):
    b = base_of(field).lower()
    every = {f.lower() for f in GRAPH | LOGANALYTICS | EVENTHUB}
    # also compare on the last path segment, for nested references
    return b in every or b.split(".")[-1] in {f.lower().split(".")[-1] for f in every}


def audit(path):
    findings = []
    files = sorted(pathlib.Path(path, "rules/cloud/azure/audit_logs").glob("*.yml"))
    for f in files:
        try:
            rule = yaml.safe_load(f.read_text(encoding="utf-8"))
        except Exception as exc:
            findings.append((f.name, "PARSE", "", f"cannot parse: {exc}"))
            continue
        if not rule:
            continue
        detection = rule.get("detection") or {}
        for block, field, value in leaf_fields(detection):
            values = value if isinstance(value, list) else [value]
            for v in values:
                if isinstance(v, str) and v.strip().lower() in PLACEHOLDERS:
                    findings.append((
                        f.name, "CERTAIN", f"{block}.{field}",
                        f"value {v!r} is a template placeholder, not data"))
            if base_of(field) in CONVENTIONS:
                continue
            if not known_anywhere(field):
                grade = "WEAK" if known_case_insensitively(field) else "LIKELY"
                why = ("field exists but with different casing or nesting"
                       if grade == "WEAK" else
                       "field name appears in no known representation")
                findings.append((f.name, grade, f"{block}.{field}", why))
    return files, findings


def main():
    repo = sys.argv[1] if len(sys.argv) > 1 else "."
    files, findings = audit(repo)
    order = {"PARSE": 0, "CERTAIN": 1, "LIKELY": 2, "WEAK": 3}
    findings.sort(key=lambda x: (order.get(x[1], 9), x[0]))

    counts = collections.Counter(g for _, g, _, _ in findings)
    affected = {n for n, g, _, _ in findings if g in ("CERTAIN", "LIKELY")}

    print(f"rules audited            : {len(files)}")
    print(f"rules with a CERTAIN or LIKELY finding : {len(affected)}")
    for grade in ("PARSE", "CERTAIN", "LIKELY", "WEAK"):
        if counts.get(grade):
            print(f"  {grade:<8}: {counts[grade]}")
    print()
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
