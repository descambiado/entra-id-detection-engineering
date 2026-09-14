#!/usr/bin/env python3
"""Re-run every claim in evidence/ against the live workspace, and freeze the result.

Why this exists: the lab is temporary. The Azure credit runs out on 2026-09-19
and the workspace keeps 30 days of retention from 2026-09-07, so every sentence
in evidence/ that reads "returns N rows" stops being checkable shortly after.
Anyone reading those files later, including us, would have to take them on trust.

So the claims are declared here with the query that produced them and the count
they are supposed to give. Running this while the lab is alive proves they still
hold. Running it after the lab dies fails honestly rather than pretending.

A claim that fails is not automatically wrong. Retention ages events out, so a
count can legitimately drop to zero. The report says which, it does not guess.

Run:  py freeze_evidence.py [--out ../evidence/frozen]
"""
import argparse
import datetime
import json
import pathlib
import sanitize
import shutil
import subprocess
import sys

# Discovered at run time rather than written down. The id is not a secret, you
# still need credentials to query it, but a public file has no reason to carry
# an identifier for someone's workspace.
WORKSPACE_NAME = "law-detection-lab"
RESOURCE_GROUP = "rg-detection-lab"


def workspace_id():
    az = shutil.which("az")
    if not az:
        return None
    out = subprocess.run([az, "monitor", "log-analytics", "workspace", "show",
                          "-g", RESOURCE_GROUP, "-n", WORKSPACE_NAME,
                          "--query", "customerId", "-o", "tsv"], capture_output=True)
    if out.returncode != 0:
        return None
    return out.stdout.decode("utf-8", "replace").strip() or None

EN_DASH = chr(0x2013)
UPDATE_REAL = "Update application " + EN_DASH + " Certificates and secrets management "
CREATE_REAL = "Create application " + EN_DASH + " Certificates and secrets management "

CLAIMS = [
    dict(id="6247-hyphen-exact",
         says="the value SigmaHQ #6247 merged matches nothing",
         kql="AuditLogs | where OperationName == 'Update application - Certificates and secrets management' | count",
         expect=0, cited="sigma-6247-reversed-a-correct-dash.md"),
    dict(id="6247-hyphen-caseless",
         says="and case is not the cause, =~ gives the same",
         kql="AuditLogs | where OperationName =~ 'Update application - Certificates and secrets management' | count",
         expect=0, cited="sigma-6247-reversed-a-correct-dash.md"),
    dict(id="6247-endash-real",
         says="the export emits the en dash and a trailing space",
         kql="AuditLogs | where OperationName == '" + UPDATE_REAL + "' | count",
         expect=1, cited="sigma-6247-reversed-a-correct-dash.md"),
    dict(id="6247-slash-value",
         says="the other value in that rule is not an operation name",
         kql="AuditLogs | where OperationName == 'Update Service principal/Update Application' | count",
         expect=0, cited="sigma-6247-reversed-a-correct-dash.md"),
    dict(id="microsoft-fragment",
         says="Microsoft's dash free fragment predicate works",
         kql="AuditLogs | where OperationName has_any ('Add service principal','Certificates and secrets management') | count",
         expect=7, cited="sigma-6247-reversed-a-correct-dash.md"),
    dict(id="6294-proposal",
         says="the fix proposed in SigmaHQ #6294 catches the update and only the update",
         kql="AuditLogs | where OperationName contains 'Update application' and OperationName contains 'Certificates and secrets management' | count",
         expect=1, cited="sigma-6247-reversed-a-correct-dash.md"),
    dict(id="6294-excludes-create",
         says="and deliberately does not reach the create form, which is a different rule's job",
         kql="AuditLogs | where OperationName == '" + CREATE_REAL + "' and OperationName contains 'Update application' | count",
         expect=0, cited="sigma-6247-reversed-a-correct-dash.md"),
    dict(id="create-form-is-real",
         says="the create form is real and uncovered by any rule in SigmaHQ or Elastic",
         kql="AuditLogs | where OperationName == '" + CREATE_REAL + "' | count",
         expect=2, cited="elastic-app-credential-rule-cannot-fire.md"),
    dict(id="6142-startswith",
         says="the predicate in SigmaHQ #6142 matches a real credential addition",
         kql="AuditLogs | where OperationName startswith 'Add service principal credentials' | count",
         expect=1, cited="comentario-sigma-6142-logs.md"),
    dict(id="5993-add-member-from",
         says="the value the rule had before fukusuket's fix matches nothing",
         kql="AuditLogs | where OperationName =~ 'Add member from group' | count",
         expect=0, cited="sigma-add-member-from-group.md"),
    dict(id="5993-add-member-to",
         says="while the real operation does",
         kql="AuditLogs | where OperationName =~ 'Add member to group' | count",
         expect=1, cited="sigma-add-member-from-group.md"),
]

# Deliberately absent: `contains 'Password reset'` returns 0, but the tenant has
# no password events at all, so that 0 measures nothing. It is documented as
# documentary evidence in sigma-password-reset-word-order.md and must not be
# dressed up as an executed test by appearing in this table.


def run(kql, WORKSPACE):
    # On Windows the CLI is az.cmd, so the bare name does not resolve through
    # CreateProcess. shutil.which finds whichever form this machine has.
    az = shutil.which("az")
    if not az:
        return None, "the azure cli is not on PATH, so nothing can be re-checked"
    out = subprocess.run(
        [az, "monitor", "log-analytics", "query", "-w", WORKSPACE,
         "--analytics-query", kql, "-o", "json"],
        capture_output=True)
    if out.returncode != 0:
        return None, out.stderr.decode("utf-8", "replace")[:200]
    raw = out.stdout
    for enc in ("utf-8", "cp1252"):
        try:
            data = json.loads(raw.decode(enc))
            break
        except (UnicodeDecodeError, ValueError):
            data = None
    if data is None:
        return None, "could not decode the response"
    rows = data if isinstance(data, list) else data.get("tables", [{}])[0].get("rows", [])
    if not rows:
        return 0, None
    first = rows[0]
    value = list(first.values())[0] if isinstance(first, dict) else first[0]
    try:
        return int(value), None
    except (TypeError, ValueError):
        return len(rows), None


# The events behind the counts. Frozen sanitized, because a count with no record
# under it is just a number, and the records stop existing when retention ends.
EVENTS = {
    "update-application-credentials": "AuditLogs | where OperationName contains 'Update application' and OperationName contains 'Certificates and secrets management' | take 1",
    "create-application-credentials": "AuditLogs | where OperationName contains 'Create application' and OperationName contains 'Certificates and secrets management' | take 1",
    "add-service-principal-credentials": "AuditLogs | where OperationName startswith 'Add service principal credentials' | take 1",
    "add-member-to-group": "AuditLogs | where OperationName =~ 'Add member to group' | take 1",
}
KEEP = ["AADOperationType", "ActivityDateTime", "ActivityDisplayName", "AdditionalDetails",
        "Category", "CorrelationId", "Id", "InitiatedBy", "LoggedByService", "OperationName",
        "OperationVersion", "Resource", "Result", "ResultSignature", "TargetResources"]


def freeze_events(outdir, WORKSPACE):
    """Every record is passed through sanitize and then checked again. A record
    that still leaks is not written at all, rather than written with a warning."""
    az = shutil.which("az")
    saved, refused = [], []
    d = outdir / "events"
    d.mkdir(parents=True, exist_ok=True)
    for name, kql in EVENTS.items():
        out = subprocess.run([az, "monitor", "log-analytics", "query", "-w", WORKSPACE,
                              "--analytics-query", kql, "-o", "json"], capture_output=True)
        data = None
        for enc in ("utf-8", "cp1252"):
            try:
                data = json.loads(out.stdout.decode(enc))
                break
            except (UnicodeDecodeError, ValueError):
                continue
        rows = (data if isinstance(data, list) else (data or {}).get("tables", [{}])[0].get("rows", [])) if data else []
        if not rows:
            refused.append((name, "no row in retention"))
            continue
        record = {k: rows[0][k] for k in KEEP if k in rows[0]}
        clean = sanitize.sanitize(record)
        found = sanitize.leaks(clean)
        if found:
            refused.append((name, "still leaks %s" % found[:2]))
            continue
        (d / (name + ".json")).write_text(clean + chr(10), encoding="utf-8")
        saved.append(name)
    return saved, refused


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default=str(pathlib.Path(__file__).parent.parent / "evidence" / "frozen"))
    args = ap.parse_args()
    stamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    ws = workspace_id()
    if not ws:
        print("the workspace is gone or the cli is not signed in, nothing can be re-checked")
        return 1

    results, bad = [], 0
    for c in CLAIMS:
        got, err = run(c["kql"], ws)
        ok = (got == c["expect"]) and err is None
        bad += 0 if ok else 1
        results.append(dict(c, got=got, error=err, ok=ok))
        mark = "ok  " if ok else "FAIL"
        shown = c["kql"].replace(EN_DASH, "<U+2013>")
        print("[%s] %-22s expected %-3s got %-5s %s" % (mark, c["id"], c["expect"], got, c["says"]))
        if err:
            print("       error: %s" % err)
        if not ok and err is None:
            print("       query: %s" % shown)

    outdir = pathlib.Path(args.out)
    outdir.mkdir(parents=True, exist_ok=True)
    report = dict(frozen_at=stamp, workspace_retention_days=30, claims=results,
                  passing=len(results) - bad, total=len(results))
    (outdir / "claims.json").write_text(
        json.dumps(report, ensure_ascii=False, indent=2) + chr(10), encoding="utf-8")
    print()
    print("%d of %d claims still hold, frozen at %s" % (len(results) - bad, len(results), stamp))
    print("written to %s" % (outdir / "claims.json"))

    saved, refused = freeze_events(outdir, ws)
    print()
    print("events frozen sanitized: %s" % (", ".join(saved) if saved else "none"))
    for name, why in refused:
        print("  not written, %s: %s" % (name, why))
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
