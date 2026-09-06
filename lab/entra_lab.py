#!/usr/bin/env python3
"""
entra_lab.py - capture Entra ID audit events from a live tenant.

Standard library only. No pip install needed. Run with: py entra_lab.py <command>

WHY THIS EXISTS
---------------
Reading the Entra portal by hand is slow and, worse, it is unsafe to conclude
from. Audit ingestion is not instant and it is not uniform across services.

On 2026-08-20 a rule in this repo was declared broken from what the portal was
showing at 04:36. The verdict was wrong: the missing records from the
Authentication Methods service landed around 05:05, and they proved the rule had
been correct all along.

The `watch` command exists so that cannot happen again. It refuses to give a
verdict until the event stream has gone quiet for several consecutive polls.
A partial answer is worse than no answer, because a partial answer looks like
a finding.

SETUP
-----
See README.md in this directory. You need an app registration with the
AuditLog.Read.All application permission and admin consent granted, then three
environment variables:

    ENTRA_TENANT_ID
    ENTRA_CLIENT_ID
    ENTRA_CLIENT_SECRET

Never hardcode the secret. Never commit it.
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import pathlib
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

GRAPH = "https://graph.microsoft.com/v1.0"
LOGIN = "https://login.microsoftonline.com"
CAPTURE_DIR = pathlib.Path(__file__).parent / "captures"

# Transient conditions. Throttling and gateway errors must not be fatal: a watch
# can legitimately run for half an hour, and dying at minute 25 would throw away
# everything captured so far.
RETRYABLE = {429, 500, 502, 503, 504}


class GraphError(RuntimeError):
    """Non-retryable Graph failure. Carries a message already worth printing."""


class Graph:
    """
    Thin Graph client: caches the token, refreshes it, retries transient errors.

    Token lifetime is roughly an hour. Fetching it once at the start of a watch
    means a long run starts failing with 401 halfway through, exactly when
    `--timeout 3600` is being used for a service known to lag. So the token is
    refreshed on demand instead.
    """

    def __init__(self) -> None:
        self.tenant = os.environ.get("ENTRA_TENANT_ID")
        self.client_id = os.environ.get("ENTRA_CLIENT_ID")
        self.secret = os.environ.get("ENTRA_CLIENT_SECRET")

        missing = [
            name
            for name, value in (
                ("ENTRA_TENANT_ID", self.tenant),
                ("ENTRA_CLIENT_ID", self.client_id),
                ("ENTRA_CLIENT_SECRET", self.secret),
            )
            if not value
        ]
        if missing:
            sys.exit(
                "Missing environment variables: "
                + ", ".join(missing)
                + "\nSee lab/README.md for setup."
            )

        self._token: str | None = None
        self._expires_at = 0.0

    # -- auth ----------------------------------------------------------------

    def token(self) -> str:
        # Refresh a little before the real expiry so a request never starts with
        # a token that dies mid-flight.
        if self._token and time.monotonic() < self._expires_at - 120:
            return self._token

        body = urllib.parse.urlencode(
            {
                "client_id": self.client_id,
                "client_secret": self.secret,
                "scope": "https://graph.microsoft.com/.default",
                "grant_type": "client_credentials",
            }
        ).encode()
        req = urllib.request.Request(
            f"{LOGIN}/{self.tenant}/oauth2/v2.0/token",
            data=body,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                payload = json.loads(resp.read())
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode("utf-8", "replace")
            raise GraphError(f"Token request failed ({exc.code}).\n{detail}") from exc
        except urllib.error.URLError as exc:
            raise GraphError(f"Could not reach the token endpoint: {exc.reason}") from exc

        self._token = payload["access_token"]
        self._expires_at = time.monotonic() + float(payload.get("expires_in", 3600))
        return self._token

    # -- requests ------------------------------------------------------------

    def get(self, url: str, attempts: int = 4) -> dict:
        last: str = "no attempt made"
        for attempt in range(attempts):
            req = urllib.request.Request(
                url, headers={"Authorization": f"Bearer {self.token()}"}
            )
            try:
                with urllib.request.urlopen(req, timeout=60) as resp:
                    return json.loads(resp.read())
            except urllib.error.HTTPError as exc:
                detail = exc.read().decode("utf-8", "replace")

                if exc.code == 401:
                    # Token rejected. Drop it and let the next attempt mint one.
                    self._token = None
                    last = f"401 unauthorized\n{detail}"
                elif exc.code == 403:
                    raise GraphError(
                        f"403 forbidden.\n{detail}\n\n"
                        "A 403 here almost always means the app registration is "
                        "missing the AuditLog.Read.All APPLICATION permission, "
                        "or that admin consent was never granted. Adding the "
                        "permission is not enough on its own: the 'Grant admin "
                        "consent' button has to be clicked. See lab/README.md."
                    ) from exc
                elif exc.code in RETRYABLE:
                    # Retry-After is normally an integer number of seconds, but
                    # the spec also allows an HTTP date. Do not crash on one.
                    try:
                        wait = float(exc.headers.get("Retry-After") or 2 ** attempt)
                    except (TypeError, ValueError):
                        wait = float(2 ** attempt)
                    wait = min(wait, 120.0)
                    last = f"{exc.code} transient\n{detail}"
                    print(
                        f"    (transient {exc.code}, retrying in {wait:.0f}s)",
                        file=sys.stderr,
                        flush=True,
                    )
                    time.sleep(wait)
                    continue
                else:
                    raise GraphError(f"Graph request failed ({exc.code}).\n{detail}") from exc
            except urllib.error.URLError as exc:
                last = f"network error: {exc.reason}"
                time.sleep(2 ** attempt)
                continue

            time.sleep(2 ** attempt)

        raise GraphError(f"Giving up after {attempts} attempts. Last error:\n{last}")

    # -- endpoints -----------------------------------------------------------

    def audits(self, since: dt.datetime, max_pages: int = 10) -> list[dict]:
        stamp = since.strftime("%Y-%m-%dT%H:%M:%SZ")
        query = urllib.parse.urlencode(
            {"$filter": f"activityDateTime ge {stamp}", "$top": "100"}
        )
        return self._paged(f"{GRAPH}/auditLogs/directoryAudits?{query}", max_pages)

    def signins(self, since: dt.datetime, max_pages: int = 5) -> list[dict]:
        stamp = since.strftime("%Y-%m-%dT%H:%M:%SZ")
        query = urllib.parse.urlencode(
            {"$filter": f"createdDateTime ge {stamp}", "$top": "50"}
        )
        return self._paged(f"{GRAPH}/auditLogs/signIns?{query}", max_pages)

    def _paged(self, url: str | None, max_pages: int) -> list[dict]:
        events: list[dict] = []
        for _ in range(max_pages):
            if not url:
                break
            payload = self.get(url)
            events.extend(payload.get("value", []))
            url = payload.get("@odata.nextLink")
        return events


# --------------------------------------------------------------------------
# rendering
# --------------------------------------------------------------------------

def actor_of(event: dict) -> str:
    """
    Who triggered this. Deliberately reports app actors explicitly.

    An admin action in the portal can be recorded with a Microsoft first party
    service principal as the initiator rather than the human. A rule that reads
    initiatedBy.user.userPrincipalName gets an empty string in that case and
    silently attributes nothing. That is a real failure mode found in this
    tenant on 2026-08-20, so this function never hides it.
    """
    initiated = event.get("initiatedBy") or {}
    user = (initiated.get("user") or {}).get("userPrincipalName")
    if user:
        return user
    app = (initiated.get("app") or {}).get("displayName")
    if app:
        return f"[app] {app}"
    return "[unattributed]"


def summarise(event: dict) -> str:
    targets = []
    for target in event.get("targetResources") or []:
        name = target.get("userPrincipalName") or target.get("displayName")
        if name:
            targets.append(name)
    return (
        f"  {event.get('activityDateTime', '?')}  "
        f"{event.get('activityDisplayName', '?')}\n"
        f"      category={event.get('category', '?')}  "
        f"service={event.get('loggedByService', '?')}  "
        f"result={event.get('result', '?')}\n"
        f"      actor={actor_of(event)}\n"
        f"      targets={', '.join(targets) if targets else '(none)'}\n"
        f"      correlationId={event.get('correlationId', '?')}  id={event.get('id', '?')}"
    )


def save(events: list[dict], label: str) -> pathlib.Path:
    CAPTURE_DIR.mkdir(parents=True, exist_ok=True)
    name = f"{dt.datetime.now(dt.timezone.utc):%Y%m%dT%H%M%SZ}-{label}.capture.json"
    path = CAPTURE_DIR / name
    path.write_text(json.dumps(events, indent=2, ensure_ascii=False), encoding="utf-8")
    return path


# --------------------------------------------------------------------------
# commands
# --------------------------------------------------------------------------

def cmd_recent(args: argparse.Namespace) -> None:
    graph = Graph()
    since = dt.datetime.now(dt.timezone.utc) - dt.timedelta(minutes=args.minutes)
    events = graph.audits(since)
    events.sort(key=lambda e: e.get("activityDateTime", ""))

    print(f"{len(events)} directory audit events in the last {args.minutes} min\n")
    for event in events:
        print(summarise(event))
        print()

    if events and not args.no_save:
        print(f"saved: {save(events, 'recent')}")

    print(
        "\nNOTE: this is a snapshot, not a verdict. Ingestion lag is real and "
        "uneven across services.\nIf you are about to conclude that a rule does "
        "or does not fire, use `watch` instead."
    )


def cmd_watch(args: argparse.Namespace) -> None:
    """
    Poll until the stream goes quiet, then report.

    Quiescence, not a fixed sleep, is the correct stopping condition: services
    ingest at different speeds, so a fixed wait either wastes time or lies.
    """
    graph = Graph()
    since = dt.datetime.now(dt.timezone.utc) - dt.timedelta(minutes=args.since_minutes)
    started = time.monotonic()

    print(f"Watching directory audits since {since:%Y-%m-%dT%H:%M:%SZ}")
    print(
        f"Polling every {args.interval}s. Needs {args.stable_polls} consecutive "
        f"quiet polls and at least {args.min_wait}s elapsed before it will call "
        f"the result stable.\nGo and perform the action in the portal now. "
        f"Ctrl+C to stop early.\n"
    )

    seen: dict[str, dict] = {}
    quiet_streak = 0
    stable = False
    failure: str | None = None

    try:
        while True:
            elapsed = time.monotonic() - started
            if elapsed > args.timeout:
                break

            fresh = [e for e in graph.audits(since) if e.get("id") not in seen]
            for event in fresh:
                seen[event["id"]] = event

            if fresh:
                quiet_streak = 0
                fresh.sort(key=lambda e: e.get("activityDateTime", ""))
                print(f"[+{int(elapsed):>5}s] {len(fresh)} new event(s):")
                for event in fresh:
                    print(summarise(event))
                print()
            else:
                quiet_streak += 1
                print(
                    f"[+{int(elapsed):>5}s] quiet ({quiet_streak}/{args.stable_polls})"
                    f"  total seen: {len(seen)}",
                    flush=True,
                )

            if quiet_streak >= args.stable_polls and elapsed >= args.min_wait:
                stable = True
                break

            time.sleep(args.interval)
    except KeyboardInterrupt:
        print("\nInterrupted by user.")
    except GraphError as exc:
        # Never lose a long capture to a late failure. Report, then still save.
        failure = str(exc)
        print(f"\nGraph error during watch:\n{failure}", file=sys.stderr)

    events = sorted(seen.values(), key=lambda e: e.get("activityDateTime", ""))
    print("\n" + "=" * 70)
    if failure:
        print(
            f"ABORTED by a Graph error after capturing {len(events)} event(s).\n"
            "Treat this set as incomplete. Do not conclude anything from it."
        )
    elif stable and not events:
        # "Stable with nothing in it" is the most dangerous possible output: it
        # reads like "the action produced no events" when the usual cause is
        # that the action was never performed.
        print(
            "STABLE but ZERO events were captured in the window.\n"
            "This is almost never a finding. Check, in order:\n"
            "  1. Did you actually perform the action in the portal?\n"
            "  2. Was it inside the window? Re-run with a larger --since-minutes.\n"
            "  3. Does the app registration really have consent for "
            "AuditLog.Read.All?\n"
            "Do NOT record this as evidence that an operation emits no audit event."
        )
    elif stable:
        print(
            f"STABLE. {len(events)} event(s) captured, then {args.stable_polls} "
            f"quiet polls in a row.\nSafe to draw conclusions from this set."
        )
    else:
        print(
            f"NOT STABLE. {len(events)} event(s) captured but the stream never "
            f"went quiet within the limits.\n"
            "DO NOT conclude that a rule fails to fire from this data. Records "
            "have arrived 25 minutes late in this tenant before.\n"
            "Re-run with a longer --timeout, or wait and run `recent` again."
        )
    print("=" * 70)

    if events:
        print(f"saved: {save(events, 'watch')}")


def cmd_signins(args: argparse.Namespace) -> None:
    graph = Graph()
    since = dt.datetime.now(dt.timezone.utc) - dt.timedelta(minutes=args.minutes)
    events = graph.signins(since)
    print(f"{len(events)} sign-in events in the last {args.minutes} min\n")
    for event in events:
        status = (event.get("status") or {}).get("errorCode")
        print(
            f"  {event.get('createdDateTime', '?')}  "
            f"{event.get('userPrincipalName', '?')}  "
            f"app={event.get('appDisplayName', '?')}  "
            f"ip={event.get('ipAddress', '?')}  errorCode={status}"
        )
    if events and not args.no_save:
        print(f"\nsaved: {save(events, 'signins')}")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Capture Entra ID audit events from a live tenant.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Typical loop:\n"
            "  1. py entra_lab.py watch\n"
            "  2. perform the action in the Entra portal\n"
            "  3. wait for the STABLE verdict\n"
            "  4. py match_rule.py <rule.yml> captures/<file>.capture.json\n"
        ),
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_recent = sub.add_parser("recent", help="snapshot of recent audit events")
    p_recent.add_argument("--minutes", type=int, default=30)
    p_recent.add_argument("--no-save", action="store_true")
    p_recent.set_defaults(func=cmd_recent)

    p_watch = sub.add_parser(
        "watch", help="poll until ingestion goes quiet, then give a verdict"
    )
    p_watch.add_argument("--since-minutes", type=int, default=10)
    p_watch.add_argument("--interval", type=int, default=20, help="seconds between polls")
    p_watch.add_argument(
        "--stable-polls",
        type=int,
        default=3,
        help="consecutive quiet polls required before calling it stable",
    )
    p_watch.add_argument(
        "--min-wait",
        type=int,
        default=300,
        help="minimum seconds before a stable verdict is allowed",
    )
    p_watch.add_argument(
        "--timeout",
        type=int,
        default=1800,
        help="give up after this many seconds (default 30 min)",
    )
    p_watch.set_defaults(func=cmd_watch)

    p_signins = sub.add_parser("signins", help="recent sign-in logs")
    p_signins.add_argument("--minutes", type=int, default=30)
    p_signins.add_argument("--no-save", action="store_true")
    p_signins.set_defaults(func=cmd_signins)

    args = parser.parse_args()
    try:
        args.func(args)
    except GraphError as exc:
        sys.exit(str(exc))


if __name__ == "__main__":
    main()
