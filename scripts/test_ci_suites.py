#!/usr/bin/env python3
"""The few safe isolation boundaries and conservative fallbacks are explicit."""
import json
import os
from pathlib import Path
import subprocess
import sys
import textwrap
import unittest

from ci_suites import changed_files, parse_changes, select


class SuiteSelectionTests(unittest.TestCase):
    def selection(self, *paths):
        return select([("M", (path,)) for path in paths])

    def test_ui_presentation_runs_complete_ui_suite(self):
        for path in ["auth-ui/src/components/sign-in/SignInFlow.tsx", "auth-ui/src/ui/input.tsx", "auth-ui/src/styles.css", "auth-ui/src/react/login.test.tsx"]:
            self.assertEqual(self.selection(path), {"root": False, "ui": True, "workflow": False, "security": True}, path)

    def test_root_test_only_runs_complete_root_suite(self):
        self.assertEqual(self.selection("auth_groups_test.go"), {"root": True, "ui": False, "workflow": False, "security": True})

    def test_shared_and_unknown_inputs_run_both(self):
        for path in ["auth.go", "iam/access.go", "api/openapi.json", "go.mod", "go.sum", "internal/migrations/postgres/0026.sql", "auth-ui/src/client/client.ts", "auth-ui/src/react/useLogin.ts", "auth-ui/package.json", "auth-ui/e2e/server/main_test.go", "internal/apitest/testdata/browser_test.go", "README.md", "new-area/unknown.data"]:
            result = self.selection(path)
            self.assertTrue(result["root"] and result["ui"], path)

    def test_ci_changes_run_full_and_lint(self):
        for path in [".github/workflows/ci.yaml", "scripts/ci_suites.py", "scripts/test_ci_suites.py", "scripts/check.sh"]:
            self.assertEqual(self.selection(path), {"root": True, "ui": True, "workflow": True, "security": True})

    def test_deletions_and_renames_never_narrow(self):
        for change in [("D", ("auth-ui/src/styles.css",)), ("R100", ("CHANGELOG.md", "auth-ui/src/styles.css"))]:
            self.assertEqual(select([change]), {"root": True, "ui": True, "workflow": False, "security": True})

    def test_mixed_unknown_overrides_safe_isolation(self):
        result = self.selection("auth-ui/src/styles.css", "new-area/unknown.data")
        self.assertTrue(result["root"] and result["ui"])

    def test_changelog_and_license_are_known_prose(self):
        self.assertEqual(self.selection("CHANGELOG.md", "LICENSE"), {"root": False, "ui": False, "workflow": False, "security": True})

    def test_git_records_and_read_failures(self):
        self.assertEqual(parse_changes(b"R100\0old\0new\0M\0auth.go\0"), [("R100", ("old", "new")), ("M", ("auth.go",))])
        with self.assertRaises(ValueError):
            parse_changes(b"M\0unterminated")
        with self.assertRaises(subprocess.CalledProcessError):
            changed_files("refs/heads/this-ref-must-not-exist-ci-test", "HEAD")


class RequiredGateTests(unittest.TestCase):
    def run_gate(self, flags=None, changed=None, event="workflow_dispatch", env=None):
        text = (Path(__file__).parent.parent / ".github/workflows/ci.yaml").read_text()
        gate = text.split("\n  gate:\n", 1)[1]
        code = textwrap.dedent(gate.split("python3 - <<'CHECK'\n", 1)[1].split("\n          CHECK", 1)[0])
        plan = {"root": "true", "ui": "false", "workflow": "false", "security": "true"}
        if flags is not None:
            plan = flags
        result = {"changes": {"result": "success", "outputs": plan}}
        for job, flag in {"workflows": "root", "contracts": "root", "security": "security", "auth-ui": "ui", "workflow-lint": "workflow"}.items():
            result[job] = {"result": "success" if plan.get(flag) == "true" else "skipped"}
        if changed:
            result.update(changed)
        process_env = {**os.environ, "RESULTS": json.dumps(result), "GITHUB_EVENT_NAME": event, **(env or {})}
        return subprocess.run([sys.executable, "-"], input=code, text=True, capture_output=True, env=process_env)

    def test_selected_suites_require_success(self):
        self.assertEqual(self.run_gate().returncode, 0)
        self.assertNotEqual(self.run_gate(changed={"workflows": {"result": "skipped"}}).returncode, 0)
        self.assertNotEqual(self.run_gate(changed={"security": {"result": "failure"}}).returncode, 0)
        self.assertNotEqual(self.run_gate(changed={"changes": {"result": "skipped", "outputs": {}}}).returncode, 0)

    def test_missing_or_invalid_selection_fails(self):
        for bad in [{"root": "true"}, {"root": "true", "ui": "false", "workflow": "false", "security": "unknown"}]:
            self.assertNotEqual(self.run_gate(flags=bad).returncode, 0)

    def test_pr_requires_tested_base_outputs(self):
        process = self.run_gate(event="pull_request", env={"PR_BASE_REF": "master", "PR_BASE_SHA": "a" * 40})
        self.assertNotEqual(process.returncode, 0)
        self.assertIn("tested base is missing", process.stderr)


if __name__ == "__main__":
    unittest.main()
