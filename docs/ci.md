# CI suites

Ready pull requests run against GitHub's synthetic merge of the PR and current base. The selector verifies those parents and the current remote base through the authenticated GitHub API, records the tested source and chooses complete suites. The gate checks that base again after all selected suites succeed. Drafts and master pushes do not run the main suite; an explicit manual CI request runs both suites. `CI Gate` aggregates the required results. Drafts use a different skipped-check name.

- **Root:** existing `scripts/check.sh workflows`, `scripts/check.sh contracts`, and `Required Security`. These retain real PostgreSQL/Redis/browser workflows, required test-name and zero-skip assertions, SQL/schema and generated-contract checks, govulncheck and Trivy.
- **UI:** existing auth-ui check, generated-contract check and real Playwright suite through the reusable auth-ui workflow. It runs once per selection rather than as a second independent PR trigger.

The selector is deliberately conservative. UI presentation files and UI test files may select UI alone. Root `_test.go` files may select Root alone, except UI/shared-browser fixtures. Changelog/license edits can omit source and UI suites. Every nonempty change still runs the unchanged Required Security job, including UI-only and prose changes. Root implementation, public clients/hooks/API, dependencies, schemas, CI, unknown paths, deletions and renames select both. Failure to read a diff fails the gate; it never turns an unknown change into a skipped suite.

The existing setup-go/setup-node caches already restore and save in PR/manual contexts; no master-only cache writer needs replacement. The large root/security/contract test commands are unchanged.

Release publication assigns the tag version, builds the UI package, packs it and validates export/type targets inside that tarball. It does not repeat the heavy source suites already run before merge. Manual artifact republishing remains available. The Go release is the signed source tag.

A strict required `CI Gate` status rule is proposed separately, preserving current protections. It must require an up-to-date base: after master advances, refresh and rerun before merging. Missing selections and skipped selected suites fail the gate. Workflow selection alone does not enforce repository protection.
