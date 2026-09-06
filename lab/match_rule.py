#!/usr/bin/env python3
"""
match_rule.py - does this Sigma rule actually match this real event?

Usage:
    py match_rule.py <rule.yml> <capture.json>
    py match_rule.py ../sigma/persistence/azure_ad_sp_credentials_added.yml \
        captures/20260826T173000Z-watch.capture.json

WHY THIS EXISTS
---------------
Two rules in this repo were written against operation names that do not exist,
and neither failed loudly. A detection rule that is wrong does not throw an
error. It stays silent for ever and you believe you are covered.

Concrete cases this would have caught immediately:

  azure_ad_authentication_methods_policy_modified
      wanted  OperationName 'Update authentication methods policy'
      real    'Authentication Methods Policy Update'
      wanted  Category 'Policy'
      real    'PolicyManagement'
      Two independent errors in one rule. It was discarded.

  azure_ad_sp_credentials_added
      wanted  'Add service principal credentials'
      real    'Update application - Certificates and secrets management'
              when the secret is added through the portal
      Valid, but blind to the most common path.

Point this at a capture from entra_lab.py and it tells you which field failed
and what the tenant actually emitted.

Requires pyyaml, which is already present on this machine.
"""

from __future__ import annotations

import json
import pathlib
import sys

try:
    import yaml
except ImportError:
    sys.exit("pyyaml is required:  py -m pip install pyyaml")


# Sigma field names used by azure/auditlogs rules, mapped to the shape Graph
# actually returns from /auditLogs/directoryAudits. Keys are lowercased.
FIELD_MAP: dict[str, list[str]] = {
    "properties.message": ["activityDisplayName"],
    "operationname": ["activityDisplayName"],
    "activitydisplayname": ["activityDisplayName"],
    "activitytype": ["activityDisplayName"],
    "category": ["category"],
    "properties.category": ["category"],
    "loggedbyservice": ["loggedByService"],
    "service": ["loggedByService"],
    "result": ["result"],
    "resulttype": ["result"],
    "resultreason": ["resultReason"],
    "properties.result": ["result"],
    "initiatedby.user.userprincipalname": ["initiatedBy.user.userPrincipalName"],
    "initiatedby.app.displayname": ["initiatedBy.app.displayName"],
    "targetresources.userprincipalname": ["targetResources[].userPrincipalName"],
    "targetresources.displayname": ["targetResources[].displayName"],
    "targetresources.modifiedproperties.displayname": [
        "targetResources[].modifiedProperties[].displayName"
    ],
    # Event Hub shape, used by SigmaHQ PR #5993 across the audit_logs folder.
    # These rules do `properties.targetResources|contains|all` against the whole
    # serialized container, because the interesting values live inside an array
    # of objects and there is no flat field to bind to.
    "properties.targetresources": ["targetResources"],
    "targetresources": ["targetResources"],
    "properties.additionaldetails": ["additionalDetails"],
    "additionaldetails": ["additionalDetails"],
}


def dig(event: dict, path: str) -> list:
    """Resolve a dotted path. `[]` means iterate a list and keep going."""
    current: list = [event]
    for part in path.split("."):
        nxt: list = []
        want_list = part.endswith("[]")
        key = part[:-2] if want_list else part
        for node in current:
            if not isinstance(node, dict):
                continue
            value = node.get(key)
            if value is None:
                continue
            if want_list and isinstance(value, list):
                nxt.extend(value)
            else:
                nxt.append(value)
        current = nxt
    return [v for v in current if v is not None]


def as_text(value) -> str:
    """Serialize containers so a `contains` test can run against them.

    `properties.targetResources` resolves to a list of dicts, not a string.
    str() on that gives Python repr with single quotes, which would silently
    change what a substring test means. JSON is what the log actually is.
    """
    if isinstance(value, (dict, list)):
        return json.dumps(value, ensure_ascii=False)
    return str(value)


def compare(actual, expected, modifier: str | None) -> bool:
    a, e = as_text(actual), as_text(expected)
    if modifier == "contains":
        return e.lower() in a.lower()
    if modifier == "startswith":
        return a.lower().startswith(e.lower())
    if modifier == "endswith":
        return a.lower().endswith(e.lower())
    return a.lower() == e.lower()


UNSUPPORTED_MODIFIERS = {"re", "base64", "base64offset", "cidr", "gt", "gte", "lt", "lte"}


def check_field(event: dict, sigma_field: str, expected) -> dict:
    # Modifiers chain: `field|contains|all`. Splitting on the FIRST pipe only
    # leaves modifier == "contains|all", which matches no branch in compare()
    # and therefore falls through to exact equality. That is the same defect
    # already fixed once for `re`/`base64`/`cidr`: a rule that works would be
    # reported as not firing. Parse every segment instead.
    parts = sigma_field.split("|")
    base = parts[0]
    mods = [m.strip().lower() for m in parts[1:] if m.strip()]
    require_all = "all" in mods
    match_mods = [m for m in mods if m != "all"]
    modifier = match_mods[0] if match_mods else None
    if len(match_mods) > 1:
        modifier = "__multiple__"

    # A modifier this script cannot evaluate must NOT fall through to exact
    # string equality. That would report NO_MATCH for a rule that works fine,
    # which is precisely the wrong conclusion this whole tool exists to prevent.
    if modifier in UNSUPPORTED_MODIFIERS or modifier == "__multiple__":
        graph_paths = FIELD_MAP.get(base.lower()) or []
        actual: list = []
        for path in graph_paths:
            actual.extend(dig(event, path))
        return {
            "field": sigma_field,
            "status": "UNSUPPORTED",
            "expected": expected if isinstance(expected, list) else [expected],
            "actual": actual,
        }

    graph_paths = FIELD_MAP.get(base.lower())
    if graph_paths is None:
        return {
            "field": sigma_field,
            "status": "UNKNOWN_FIELD",
            "expected": expected,
            "actual": [],
        }

    actual: list = []
    for path in graph_paths:
        actual.extend(dig(event, path))

    wanted = expected if isinstance(expected, list) else [expected]
    # `|all` means every listed value must be found, not just one of them.
    quantify = all if require_all else any
    matched = quantify(
        any(compare(a, w, modifier) for a in actual if a is not None) for w in wanted
    )
    return {
        "field": sigma_field,
        "status": "MATCH" if matched else "NO_MATCH",
        "expected": wanted,
        "actual": actual,
    }


def evaluate(rule: dict, event: dict) -> tuple[str, list[dict], list[str]]:
    """
    Returns one of three verdicts, never a bare boolean.

    FIRES         every field matched
    NO            at least one field demonstrably did not match
    INDETERMINATE something could not be evaluated honestly

    The third case matters. Collapsing "I cannot tell" into "it does not fire"
    is how a working rule gets declared dead.
    """
    detection = rule.get("detection") or {}
    condition = str(detection.get("condition", "")).strip()

    notes: list[str] = []
    indeterminate = False

    if condition and condition != "selection":
        notes.append(
            f"condition is '{condition}', not a plain 'selection'. Only the "
            "'selection' block is evaluated here, so the verdict cannot be trusted "
            "on its own. Read the rule."
        )
        indeterminate = True

    selection = detection.get("selection")
    if not isinstance(selection, dict):
        notes.append(
            "no dict 'selection' block found (a list of maps, or keywords, is not "
            "supported). Nothing was evaluated."
        )
        return "INDETERMINATE", [], notes

    results = [check_field(event, field, expected) for field, expected in selection.items()]

    for r in results:
        if r["status"] == "UNSUPPORTED":
            notes.append(
                f"'{r['field']}' uses a modifier this script cannot evaluate. "
                "It was NOT counted either way. Check it by hand."
            )
            indeterminate = True
        elif r["status"] == "UNKNOWN_FIELD":
            notes.append(
                f"'{r['field']}' is not in the field map. Either the rule has a "
                "typo, or this script does not know the field yet. Those are very "
                "different problems: find out which before acting."
            )
            indeterminate = True

    if not results:
        return "INDETERMINATE", results, notes
    if any(r["status"] == "NO_MATCH" for r in results):
        # A concrete mismatch is a real answer even if another field was
        # unevaluable: the rule cannot fire on this event either way.
        return "NO", results, notes
    if indeterminate:
        return "INDETERMINATE", results, notes
    return "FIRES", results, notes


FLAGS = {
    "MATCH": "OK  ",
    "NO_MATCH": "FAIL",
    "UNKNOWN_FIELD": "????",
    "UNSUPPORTED": "SKIP",
}

VERDICT_TEXT = {
    "FIRES": "RULE FIRES",
    "NO": "rule does not fire",
    "INDETERMINATE": "CANNOT TELL, see notes. Do not record this as a result.",
}


def render(event: dict, results: list[dict], verdict: str, notes: list[str]) -> None:
    print(
        f"  {event.get('activityDateTime', '?')}  "
        f"{event.get('activityDisplayName', '?')}  "
        f"[{event.get('category', '?')} / {event.get('loggedByService', '?')}]"
    )
    for r in results:
        print(f"    {FLAGS[r['status']]}  {r['field']}")
        if r["status"] == "MATCH":
            continue
        print(f"          rule wants : {r['expected']}")
        if r["status"] != "UNKNOWN_FIELD":
            actual = r["actual"] if r["actual"] else "(field absent from event)"
            print(f"          event has  : {actual}")
    for note in notes:
        print(f"    NOTE: {note}")
    print(f"    => {VERDICT_TEXT[verdict]}\n")


USAGE = "usage: py match_rule.py <rule.yml> <capture.json>"


def main() -> None:
    if len(sys.argv) != 3:
        sys.exit(USAGE)

    rule_path = pathlib.Path(sys.argv[1])
    capture_path = pathlib.Path(sys.argv[2])
    for path in (rule_path, capture_path):
        if not path.is_file():
            sys.exit(f"Not a file: {path}\n{USAGE}")

    try:
        rule = yaml.safe_load(rule_path.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        sys.exit(f"Could not parse the rule as YAML:\n{exc}")
    if not isinstance(rule, dict):
        sys.exit(f"{rule_path} did not parse into a mapping. Is it a Sigma rule?")

    try:
        payload = json.loads(capture_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        sys.exit(f"Could not parse the capture as JSON:\n{exc}")
    events = payload if isinstance(payload, list) else [payload]

    print(f"\nRule    : {rule.get('title', rule_path.name)}")
    print(f"File    : {rule_path}")
    print(f"Capture : {capture_path}  ({len(events)} event(s))\n")
    print("-" * 70)

    scored = []
    for event in events:
        verdict, results, notes = evaluate(rule, event)
        matched = sum(1 for r in results if r["status"] == "MATCH")
        scored.append((verdict, matched, event, results, notes))

    hits = [s for s in scored if s[0] == "FIRES"]
    unclear = [s for s in scored if s[0] == "INDETERMINATE"]

    for _, _, event, results, notes in hits:
        render(event, results, "FIRES", notes)

    # An event that could not be evaluated is always worth showing, even when
    # something else fired. Silence about it would be the dishonest option.
    for _, _, event, results, notes in unclear:
        render(event, results, "INDETERMINATE", notes)

    # When nothing fires, "0 of 4" alone is useless. The point of this tool is
    # the diff: what the rule wanted versus what the tenant actually emitted.
    if not hits and not unclear:
        candidates = sorted(scored, key=lambda s: s[1], reverse=True)[:5]
        print("Nothing fired. Closest candidates, best first:\n")
        for _, _, event, results, notes in candidates:
            render(event, results, "NO", notes)

    print("-" * 70)
    print(f"{len(hits)} of {len(events)} event(s) would fire this rule.")
    if unclear:
        print(
            f"{len(unclear)} event(s) could NOT be evaluated honestly. Those are "
            "not misses, they are unknowns. Read the notes above."
        )
    if not hits:
        print(
            "\nZero confirmed hits. Two very different explanations, do not "
            "confuse them:\n"
            "  1. The rule is genuinely wrong. The diffs above show which field.\n"
            "  2. The capture does not contain the action, or ingestion was still\n"
            "     in flight. Confirm entra_lab.py reported STABLE before you\n"
            "     declare a rule dead. That mistake has already been made here."
        )


if __name__ == "__main__":
    main()
