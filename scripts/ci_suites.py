#!/usr/bin/env python3
"""Select AuthKit's two coherent suites; uncertainty runs both."""
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


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base")
    parser.add_argument("--head")
    parser.add_argument("--full", action="store_true")
    parser.add_argument("--github-output", type=Path)
    args = parser.parse_args()
    if args.full:
        result = {"root": True, "ui": True, "workflow": True, "security": True}
    else:
        if not args.base or not args.head:
            parser.error("--base and --head are required without --full")
        result = select(changed_files(args.base, args.head))
    print(json.dumps(result, sort_keys=True))
    if args.github_output:
        with args.github_output.open("a") as output:
            for name, enabled in result.items():
                output.write(f"{name}={str(enabled).lower()}\n")


if __name__ == "__main__":
    main()
