#!/usr/bin/env python3
"""Strip identifiers out of a captured Entra audit record so it can be published.

Written 2026-09-14 after shipping a leak the day before. The first attempt at
this replaced a correlation GUID before replacing the longer string that
contained it, so the record id kept the internal shard and sequence after the GUID, and
the verification said "no leaks" because it only looked for the full original
strings. Both mistakes are fixed here and both are tests.

Two rules this module exists to enforce:

  1. **Longest first.** Replacements are applied from longest key to shortest,
     never in dict order, so a short value can never eat the tail of a longer
     one that contains it.
  2. **Verify against a shape, not a list.** `leaks()` looks for anything that
     still looks like a real identifier, so it catches values nobody thought to
     put on a list. Checking only for known originals is how the first leak got
     through.

No real identifier appears anywhere in this file. Everything is discovered from
the record at runtime, which is also why this can live in a public repo.
"""
import json
import re

GUID = re.compile(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}")
IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
# Matches plain UPNs and the Entra guest form, which splices the original
# address into the local part around an upper case EXT marker.
UPN = re.compile(r"[A-Za-z0-9._%+\-]+(?:#EXT#)?@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")
# Azure AD record ids carry an internal shard and sequence after the GUID.
# Azure AD record ids look like Directory_<guid>_<shard>_<sequence>. The shard and
# sequence are internal values that a GUID substitution alone does not remove.
RECORD_ID_PREFIX = "Directory_"
RECORD_ID_PLACEHOLDER = "Directory_REDACTED"

PLACEHOLDER_GUID = "{0}{0}{0}{0}{0}{0}{0}{0}-{0}{0}{0}{0}-{0}{0}{0}{0}-{0}{0}{0}{0}-{0}{0}{0}{0}{0}{0}{0}{0}{0}{0}{0}{0}"
# RFC 5737 TEST-NET-3, reserved for documentation and safe to publish.
PLACEHOLDER_IP = "203.0.113.{}"
PLACEHOLDER_UPN = "user{}@contoso.onmicrosoft.com"

# Free text fields that name real objects. Redacted by default because no
# pattern can tell 'app-registration-7' from a customer's application name.
NAME_KEYS = {"displayName", "userPrincipalName", "servicePrincipalName"}
# Keys whose whole value is an internal identifier rather than a name.
ID_KEYS = {"Id"}
# AdditionalDetails is a list of {key, value} pairs. The User-Agent in it carries
# the operating system build and client version, which fingerprints the machine.
# Found 2026-09-14 by an independent sweep after this module reported clean.
SENSITIVE_DETAIL_KEYS = {"User-Agent"}
# Credential blobs embed a name inside a flat string rather than a JSON key, as
# KeyIdentifier=<guid>,KeyType=Password,KeyUsage=Verify,DisplayName=<name>, so
# the structural pass over keys never sees it.
BLOB_NAME_PREFIX = "DisplayName="


def _walk_strings(obj):
    if isinstance(obj, str):
        yield obj
    elif isinstance(obj, dict):
        for v in obj.values():
            yield from _walk_strings(v)
    elif isinstance(obj, list):
        for v in obj:
            yield from _walk_strings(v)


def collect(record):
    """Every identifier found anywhere in the record, including inside strings
    that hold embedded JSON, which is how Log Analytics returns these columns."""
    text = json.dumps(record, ensure_ascii=False)
    found = {"guid": [], "ip": [], "upn": []}
    for g in GUID.findall(text):
        if g.lower() not in [x.lower() for x in found["guid"]]:
            found["guid"].append(g)
    for i in IPV4.findall(text):
        if i not in found["ip"]:
            found["ip"].append(i)
    for u in UPN.findall(text):
        if u not in found["upn"]:
            found["upn"].append(u)
    return found


def build_map(found):
    """Deterministic placeholders. Same input always gives the same output, so
    two records from the same tenant stay consistent with each other."""
    mapping = {}
    for n, g in enumerate(found["guid"], 1):
        mapping[g] = PLACEHOLDER_GUID.format(str(n % 10))
    for n, i in enumerate(found["ip"], 10):
        mapping[i] = PLACEHOLDER_IP.format(n)
    for n, u in enumerate(found["upn"], 1):
        mapping[u] = PLACEHOLDER_UPN.format(n)
    return mapping


def apply_map(text, mapping):
    """Longest key first. This is the whole point of the function."""
    for key in sorted(mapping, key=len, reverse=True):
        text = text.replace(key, mapping[key])
    return text


def _redact_names(obj):
    """Blank out object names structurally, including inside the embedded JSON
    that Log Analytics returns as a string in TargetResources and InitiatedBy.
    Done on the parsed object rather than with a regex over the text, because
    escaping a pattern through three layers of quoting is how mistakes happen."""
    if isinstance(obj, dict):
        if obj.get("key") in SENSITIVE_DETAIL_KEYS and "value" in obj:
            return dict(obj, value="REDACTED")
        red = {}
        for k, v in obj.items():
            if k in NAME_KEYS and isinstance(v, str):
                red[k] = "REDACTED"
            elif k in ID_KEYS and isinstance(v, str) and v.startswith(RECORD_ID_PREFIX):
                red[k] = RECORD_ID_PLACEHOLDER
            else:
                red[k] = _redact_names(v)
        return red
    if isinstance(obj, list):
        return [_redact_names(v) for v in obj]
    if isinstance(obj, str):
        try:
            inner = json.loads(obj)
        except (ValueError, TypeError):
            return obj
        if isinstance(inner, (dict, list)):
            return json.dumps(_redact_names(inner), ensure_ascii=False)
        return obj
    return obj


def _scrub_blob_names(text):
    """Names spliced into a flat credential string, which no key walk reaches."""
    return re.sub(BLOB_NAME_PREFIX + "[^],]*", BLOB_NAME_PREFIX + "REDACTED", text)




def sanitize(record, redact_names=True):
    mapping = build_map(collect(record))
    payload = _redact_names(record) if redact_names else record
    text = json.dumps(payload, ensure_ascii=False, indent=2)
    # Azure AD record ids carry an internal shard and sequence after the GUID.
    # This is the piece that survived the first attempt and was reported clean.
    text = apply_map(text, mapping)
    if redact_names:
        text = _scrub_blob_names(text)
    return text


def leaks(text, allow=()):
    """What still looks like a real identifier. Shape based on purpose."""
    allow = set(allow) | {PLACEHOLDER_UPN.format(n) for n in range(1, 10)}
    out = []
    for g in set(GUID.findall(text)):
        body = g.replace("-", "")
        if len(set(body)) > 1:                      # a placeholder is all one digit
            out.append(("guid", g))
    for i in set(IPV4.findall(text)):
        if not i.startswith("203.0.113."):
            out.append(("ip", i))
    for u in set(UPN.findall(text)):
        if u not in allow:
            out.append(("upn", u))
    if "#EXT#" in text:
        out.append(("guest-upn-marker", "#EXT#"))
    for m in re.finditer(RECORD_ID_PREFIX + r"(?!REDACTED)\S+", text):
        out.append(("record-id-shard", m.group(0)[:40]))
    return sorted(out)
