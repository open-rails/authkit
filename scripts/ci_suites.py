#!/usr/bin/env python3
"""Select AuthKit's suites by PR kind; within a selection, uncertainty runs both."""
from __future__ import annotations

import argparse
import json
from pathlib import Path, PurePosixPath
import subprocess


def parse_changes(raw: bytes) -> list[tuple[str, tuple[str, ...]]]:
    fields = raw.decode().split("\0")
    if fields[-1] != "":
        raise ValueError("unterminated git change record")
    fields.pop()
    changes = []
    while fields:
        status = fields.pop(0)
        count = 2 if status.startswith(("R", "C")) else 1
        if len(fields) < count:
            raise ValueError("incomplete git change record")
        paths = tuple(fields[:count])
        del fields[:count]
        if not status or any(not p or PurePosixPath(p).is_absolute() or ".." in PurePosixPath(p).parts for p in paths):
            raise ValueError("invalid git change record")
        changes.append((status, paths))
    return changes


def changed_files(base: str, head: str) -> list[tuple[str, tuple[str, ...]]]:
    raw = subprocess.check_output([
        "git", "diff", "--name-status", "-z", "--find-renames", f"{base}...{head}", "--",
    ], stderr=subprocess.PIPE)
    return parse_changes(raw)


def select(changes: list[tuple[str, tuple[str, ...]]]) -> dict[str, bool]:
    root = ui = workflow = False
    for status, paths in changes:
        workflow |= any(p.startswith((".github/", "scripts/")) for p in paths)
        if status not in {"A", "M"}:
            root = ui = True
            continue
        path = paths[0]
        if path in {"CHANGELOG.md", "LICENSE", "auth-ui/CHANGELOG.md", "auth-ui/LICENSE"}:
            continue
        if path.startswith(("auth-ui/src/components/", "auth-ui/src/ui/", "auth-ui/src/locales/")) or path in {"auth-ui/src/styles.css", "auth-ui/src/appearance.ts"}:
            ui = True
        elif path.startswith("auth-ui/") and path.endswith((".test.ts", ".test.tsx", ".spec.ts", ".spec.tsx")) and not path.startswith("auth-ui/e2e/server/"):
            ui = True
        elif path.endswith("_test.go") and not path.startswith(("auth-ui/", "internal/apitest/testdata/")):
            root = True
        else:
            # Shared/API/dependency/schema/CI inputs and unknown paths are full.
            root = ui = True
    return {"root": root, "ui": ui, "workflow": workflow, "security": bool(changes)}


def pr_kind(base_ref: str, head_ref: str, same_repo: bool) -> str:
    """light: feature into an RC. full: an RC into master. selected: release work. rejected: anything else."""
    if base_ref.startswith("rc/"):
        return "light"
    if base_ref == "master":
        if same_repo and head_ref.startswith("rc/"):
            return "full"
        if same_repo and head_ref.startswith("release/"):
            return "selected"
        return "rejected"
    return "selected"


REJECTED = "master takes pull requests only from rc/* and release/* branches of this repository; target the open RC named in OPEN.md"


def plan(kind: str, selected: dict[str, bool]) -> dict[str, bool]:
    if kind == "full":
        return {"root": True, "ui": True, "workflow": True, "security": True, "light": False}
    if kind == "light":
        return {"root": False, "ui": False, "workflow": selected["workflow"], "security": False, "light": True}
    if kind == "rejected":
        return {"root": False, "ui": False, "workflow": False, "security": False, "light": False}
    return selected | {"light": False}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base")
    parser.add_argument("--head")
    parser.add_argument("--full", action="store_true")
    parser.add_argument("--base-ref", help="PR base branch; with --head-ref, the PR kind decides the suites")
    parser.add_argument("--head-ref")
    parser.add_argument("--same-repo", choices=("true", "false"), default="true")
    parser.add_argument("--source-only", action="store_true", help="only check that the base accepts the head")
    parser.add_argument("--github-output", type=Path)
    args = parser.parse_args()
    kind = "selected"
    if args.base_ref is not None or args.head_ref is not None or args.source_only:
        if not args.base_ref or not args.head_ref:
            parser.error("--base-ref and --head-ref go together")
        kind = pr_kind(args.base_ref, args.head_ref, args.same_repo == "true")
    if args.source_only:
        if kind == "rejected":
            raise SystemExit(f"{args.head_ref} -> {args.base_ref}: {REJECTED}")
        print(f"{args.head_ref} -> {args.base_ref}: accepted ({kind})")
        return
    if args.full:
        result = plan("full", {})
    else:
        if not args.base or not args.head:
            parser.error("--base and --head are required without --full")
        # The diff is read for every kind: an unreadable one fails the run.
        result = plan(kind, select(changed_files(args.base, args.head)) | {"light": False})
    print(json.dumps(result | {"kind": kind}, sort_keys=True))
    if args.github_output:
        with args.github_output.open("a") as output:
            for name, enabled in result.items():
                output.write(f"{name}={str(enabled).lower()}\n")
            output.write(f"kind={kind}\n")


if __name__ == "__main__":
    main()
