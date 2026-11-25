# Branches and CI

## Branches

Feature branch → open RC → master → release tag.

- `master` is the release mainline. A release is a signed tag on a master commit; not every master commit is one.
- A release candidate is `rc/<version>`, named for the version it will become (`rc/1.53.0`), cut from master. One is open at a time; [OPEN.md](../OPEN.md) names it and what it is for. Its branch is deleted once it merges to master.
- Feature PRs target the open RC. Check OPEN.md first: an old `rc/*` is never promoted.
- master takes PRs only from `rc/*` and `release/*` branches of this repository, documentation included. The `Source branch` check refuses any other head, and `CI Gate` fails with it.

## What a ready PR runs

Drafts run nothing: stay draft until the final commit, then mark ready once. Each run tests GitHub's synthetic merge of the PR and its base. The selector verifies those parents and records the tested source; `CI Gate` aggregates the required results. Into `master` or `release/**`, the selector and `CI Gate` also check through the authenticated GitHub API that the base has not moved; a PR into an RC needs no refresh (below). Drafts use a different skipped-check name. A manual run (`workflow_dispatch`) runs every suite but satisfies no required check.

| Pull request | Runs |
|---|---|
| into `rc/**`, or `rc/*` into `master` | Every suite, whatever changed. |
| `release/*` into `master`, or into `release/**` | Suites selected from the changed paths, as below. |
| any other head into `master` | `Source branch` and `CI Gate` fail; no suite runs. |

## Suites

- **Root:** `scripts/check.sh workflows`, `scripts/check.sh contracts`, and `Required Security`. `workflows` runs every Go package's tests with `-race` against real PostgreSQL/Redis and requires every named [critical scenario](../critical/README.md) to pass, with zero skipped tests anywhere. `contracts` runs the static checks (logging; `scripts/criticalcheck`: every scenario can fail; `go vet`), sqlc generation and validation against a migrated schema, and the released-migration check. `Required Security` runs govulncheck and Trivy.
- **UI:** auth-ui's generated-contract check, typecheck, lint and real Playwright suite, through the reusable auth-ui workflow.

`scripts/check.sh light` is the service-free subset (static checks, every module compiles, released migrations) to run before pushing.

Path selection (release work only) is deliberately conservative. UI presentation files and UI test files may select UI alone. Root `_test.go` files may select Root alone, except UI/shared-browser fixtures. Changelog/license edits can omit source and UI suites. Every nonempty change still runs the Required Security job, including UI-only and prose changes. Root implementation, public clients/hooks/API, dependencies, schemas, CI, unknown paths, deletions and renames select both. Failure to read a diff fails the gate; it never turns an unknown change into a skipped suite.

Release publication assigns the tag version, builds the UI package, packs it and validates export/type targets inside that tarball. It refuses a tag that is not a commit of master, and does not repeat the source suites already run before merge. Manual artifact republishing remains available. The Go release is the signed source tag.

Rulesets require `CI Gate` on `master`, `rc/**` and `release/**`, and `Source branch` on `master`. `master` and `release/**` also require an up-to-date base: after the base advances, refresh and rerun before merging. A PR into an RC need not be refreshed when the RC advances; the RC's PR into master tests the result. Missing selections and skipped selected suites fail the gate.

## Go cache

The root suites restore the Go module and build cache (`.github/actions/go`) and never save one. The `Go cache` workflow saves it on every push to `master` and `rc/**` (or when dispatched), after building what those suites build; it runs no test. A PR can read only its base's and `master`'s caches. The newest cache of the same toolchain and `go.sum` is restored, else the newest of the toolchain.

## Dependencies

No bot opens pull requests. `Required Security` refuses a change with a fixable vulnerability: govulncheck fails on a known vulnerability the code reaches, Trivy on a high or critical one that has a fix. Updates are made deliberately, in one batch per release candidate: both Go modules (the root and `auth-ui/e2e/server`) in step, GitHub Actions pinned by commit SHA.

With Dependabot alerts enabled in the repository's settings (alerts open no pull request), GitHub's advisory feed lists what is vulnerable between runs:

```sh
gh api 'repos/open-rails/authkit/dependabot/alerts?state=open' --jq '.[] | "\(.security_advisory.severity) \(.dependency.package.name) \(.dependency.manifest_path) fixed in \(.security_vulnerability.first_patched_version.identifier // "-")"'
```
