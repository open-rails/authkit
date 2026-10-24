#!/usr/bin/env python3
"""Exercise the selector's CLI against real Git diffs; unknown changes run both suites."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile

selector = Path(__file__).with_name("ci_suites.py").resolve()
env = os.environ | {"GIT_AUTHOR_NAME": "Paul Fidika", "GIT_AUTHOR_EMAIL": "paul@fidika.com", "GIT_COMMITTER_NAME": "Paul Fidika", "GIT_COMMITTER_EMAIL": "paul@fidika.com"}
with tempfile.TemporaryDirectory(prefix="authkit-ci-selection-") as directory:
    root = Path(directory)
    def git(*args):
        return subprocess.check_output(["git", "-c", "commit.gpgsign=false", *args], cwd=root, env=env, stderr=subprocess.PIPE, text=True).strip()
    git("init", "--quiet")
    (root / "README.md").write_text("base\n")
    git("add", ".")
    git("commit", "--quiet", "-m", "CI selection fixture base")
    def select(*args):
        return json.loads(subprocess.check_output([sys.executable, str(selector), *args], cwd=root, text=True))
    for name, path, expected in [
        ("unknown source", "future/unknown.input", (True, True, False)),
        ("Go behavior test", "critical/probe_test.go", (True, False, False)),
        ("UI presentation", "auth-ui/src/components/Probe.tsx", (False, True, False)),
        ("release notes", "CHANGELOG.md", (False, False, False)),
        ("shared dependency", "go.mod", (True, True, False)),
        ("workflow policy", "scripts/guard.py", (True, True, True)),
    ]:
        base = git("rev-parse", "HEAD")
        target = root / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(name + "\n")
        git("add", ".")
        git("commit", "--quiet", "-m", name)
        result = select("--base", base, "--head", "HEAD")
        want = dict(zip(("root", "ui", "workflow"), expected)) | {"security": True}
        if result != want:
            raise SystemExit(f"{name}: {result}; expected {want}")
    # A rename crossing an isolated UI boundary is deliberately pessimistic.
    base = git("rev-parse", "HEAD")
    git("mv", "auth-ui/src/components/Probe.tsx", "unknown-ui-source.tsx")
    git("commit", "--quiet", "-m", "cross-boundary rename")
    if select("--base", base, "--head", "HEAD") != {"root": True, "ui": True, "workflow": False, "security": True}:
        raise SystemExit("cross-boundary rename skipped a suite")
    if not all(select("--full").values()):
        raise SystemExit("explicit full selection skipped a suite")
print("CI CLI selection: isolated changes, unknown/shared paths, rename, and explicit full selection passed")
