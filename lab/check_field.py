#!/usr/bin/env python3
"""
check_field.py - does this field name actually exist in the target repo?

Usage:
    py check_field.py <field-name> <path-to-repo-clone> [--ext .toml]
    py check_field.py azure.auditlogs.properties.category ../../detection-rules
    py check_field.py properties.message ../../sigma

WHY THIS EXISTS
---------------
On 2026-08-20 a rule was written for elastic/detection-rules using the field
`azure.auditlogs.category`. That field does not exist. The real one is
`azure.auditlogs.properties.category`. The rule would never have fired.

It was caught by noticing it was the only file out of 136 Azure rules using
that spelling. That check is mechanical, so it should not depend on someone
remembering to do it by eye.

Rule of thumb: if your file is the ONLY one in the repo using a field name,
you invented it. Real fields have precedent.

Standard library only.
"""

from __future__ import annotations

import argparse
import pathlib
import sys

DEFAULT_EXTS = (".toml", ".yml", ".yaml", ".json")
SKIP_DIRS = {".git", "node_modules", "__pycache__", ".venv", "venv", "site-packages"}


def scan(repo: pathlib.Path, field: str, exts: tuple[str, ...]) -> list[pathlib.Path]:
    hits: list[pathlib.Path] = []
    for path in repo.rglob("*"):
        if not path.is_file() or path.suffix.lower() not in exts:
            continue
        if any(part in SKIP_DIRS for part in path.parts):
            continue
        try:
            if field in path.read_text(encoding="utf-8", errors="ignore"):
                hits.append(path)
        except OSError:
            continue
    return hits


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[1])
    parser.add_argument("field", help="exact field name to look for")
    parser.add_argument("repo", type=pathlib.Path, help="path to the repo clone")
    parser.add_argument(
        "--ext",
        action="append",
        dest="exts",
        help="file extension to scan, repeatable. Default: .toml .yml .yaml .json",
    )
    args = parser.parse_args()

    if not args.repo.is_dir():
        sys.exit(f"Not a directory: {args.repo}")

    exts = tuple(e if e.startswith(".") else f".{e}" for e in (args.exts or DEFAULT_EXTS))
    hits = scan(args.repo, args.field, exts)

    print(f"\nfield : {args.field}")
    print(f"repo  : {args.repo.resolve()}")
    print(f"files : {len(hits)}\n")

    for path in hits[:15]:
        print(f"  {path.relative_to(args.repo)}")
    if len(hits) > 15:
        print(f"  ... and {len(hits) - 15} more")

    print()
    if len(hits) == 0:
        print(
            "VERDICT: no precedent. This field name does not appear anywhere in the\n"
            "repo. Assume you invented it or misspelled it until proven otherwise.\n"
            "A rule built on it will never fire."
        )
        sys.exit(1)
    if len(hits) == 1:
        print(
            "VERDICT: exactly one file uses this. If that file is yours, that is\n"
            "the invented-field signature. Check it against the integration's real\n"
            "field reference before opening a PR."
        )
        sys.exit(1)
    print(f"VERDICT: {len(hits)} files use this field. Precedent looks real.")


if __name__ == "__main__":
    main()
