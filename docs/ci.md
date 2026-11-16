# Branches and CI

## Branches

Feature branch → open RC → master → release tag.

- `master` is the release mainline. A release is a signed tag on a master commit; not every master commit is one.
- A release candidate is `rc/<version>`, named for the version it will become (`rc/1.53.0`), cut from master. One is open at a time; [OPEN.md](../OPEN.md) names it and what it is for. Its branch is deleted once it merges to master.
- Feature PRs target the open RC. Check OPEN.md first: an old `rc/*` is never promoted.
- master takes PRs only from `rc/*` and `release/*` branches of this repository, documentation included. The `Source branch` check refuses any other head, and `CI Gate` fails with it.

## What a ready PR runs

Drafts and master pushes run nothing: stay draft until the final commit, then mark ready once. Each run tests GitHub's synthetic merge of the PR and its current base. The selector verifies those parents and the current remote base through the authenticated GitHub API and records the tested source; `CI Gate` checks the base again after the suites and aggregates the required results. Drafts use a different skipped-check name. A manual run (`workflow_dispatch`) runs every suite but satisfies no required check.

| Pull request | Runs |
|---|---|
| into `rc/**` | Light: `scripts/check.sh light` (every Go module compiles, `go vet`, the e2e server's module follows the root's, released migrations are unchanged); auth-ui's generated-contract check, typecheck and lint; workflow lint when `.github/` or `scripts/` changed. No services, no browser, no security scan. |
| `rc/*` into `master` | Every suite, whatever changed. |
| `release/*` into `master`, or into `release/**` | Suites selected from the changed paths, as below. |
| any other head into `master` | `Source branch` and `CI Gate` fail; no suite runs. |

## Suites

- **Root:** `scripts/check.sh workflows`, `scripts/check.sh contracts`, and `Required Security`. The workflow entrypoint runs the critical Go journeys against real PostgreSQL/Redis and requires every named scenario with zero skips. Contract checks retain compiler/vet, SQL/schema and generated-contract checks; security retains govulncheck and Trivy. Browser behavior runs once in the UI suite. See [critical suite](../critical/README.md).
- **UI:** existing auth-ui check, generated-contract check and real Playwright suite through the reusable auth-ui workflow. It runs once per selection rather than as a second independent PR trigger.

Path selection (release work only) is deliberately conservative. UI presentation files and UI test files may select UI alone. Root `_test.go` files may select Root alone, except UI/shared-browser fixtures. Changelog/license edits can omit source and UI suites. Every nonempty change still runs the Required Security job, including UI-only and prose changes. Root implementation, public clients/hooks/API, dependencies, schemas, CI, unknown paths, deletions and renames select both. Failure to read a diff fails the gate; it never turns an unknown change into a skipped suite.

The existing setup-go/setup-node caches already restore and save in PR/manual contexts; no master-only cache writer needs replacement. The root behavioral command runs only the selected critical suite; security and contract checks remain separate.

Release publication assigns the tag version, builds the UI package, packs it and validates export/type targets inside that tarball. It refuses a tag that is not a commit of master, and does not repeat the source suites already run before merge. Manual artifact republishing remains available. The Go release is the signed source tag.

Rulesets require `CI Gate` on `master`, `rc/**` and `release/**`, and `Source branch` on `master`. `master` and `release/**` also require an up-to-date base: after the base advances, refresh and rerun before merging. A PR into an RC need not be refreshed when the RC advances; the RC's PR into master tests the result. Missing selections and skipped selected suites fail the gate.

## Dependencies

No bot opens pull requests. `Required Security` in the RC → master run refuses a candidate with a fixable vulnerability: govulncheck fails on a known vulnerability the code reaches, Trivy on a high or critical one that has a fix. Updates are made deliberately, in one batch per release candidate: both Go modules (the root and `auth-ui/e2e/server`) in step, GitHub Actions pinned by commit SHA.

With Dependabot alerts enabled in the repository's settings (alerts open no pull request), GitHub's advisory feed lists what is vulnerable between runs:

```sh
gh api 'repos/open-rails/authkit/dependabot/alerts?state=open' --jq '.[] | "\(.security_advisory.severity) \(.dependency.package.name) \(.dependency.manifest_path) fixed in \(.security_vulnerability.first_patched_version.identifier // "-")"'
```
