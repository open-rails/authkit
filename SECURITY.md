# Security

AuthKit is an auth library: its code runs inside other people's trust
boundaries, so every push and pull request runs the same gating pipeline.

## Reporting a vulnerability

- Do not open public issues for security problems.
- Report privately via GitHub Security Advisories ("Report a vulnerability" on
  the repo Security tab), or contact the maintainers directly.
- Include the affected version/commit, a reproduction or PoC if possible, and
  the impact you observed. We acknowledge promptly and coordinate a fix and
  disclosure timeline with you.

## CI pipeline

Four workflows in `.github/workflows/`, all triggered on `push` and
`pull_request` to `master`/`main` and by `workflow_dispatch`; the three
scanners also run on a weekly Monday schedule (06:00 / 07:00 / 08:00 UTC).

| workflow | jobs | gates? |
|---|---|---|
| `test.yaml` | `go test -race -p 1 ./...` against a real migrated Postgres (compose `issuer`) and a real Redis, then a skip gate; `sqlc generate` + `sqlc vet` + drift check on `internal/db` | yes |
| `go-sast.yaml` | `go vet ./...`, `staticcheck ./...` (pinned version) | yes |
| `codeql.yaml` | CodeQL for Go with `security-extended` + `security-and-quality` (SARIF to code scanning) | no (findings appear in the Security tab) |
| `security.yaml` | `govulncheck ./...` (pinned version; call-graph aware), Trivy fs scan (`vuln,secret,misconfig`, HIGH+ fixable) | yes |

Hardening that applies to every workflow:

- Every action is pinned to a commit SHA with a version comment; tools installed
  with `go install` are pinned to a module version. Bump deliberately.
- `.github/dependabot.yml` opens weekly bump PRs for Go modules (root and both
  adapter modules; minor/patch grouped, majors separate), the SHA-pinned
  actions, and the compose images. They merge like any other PR: the full
  `tests` check and the other gates must pass, and nothing auto-approves them.
- `step-security/harden-runner` (egress audit) is the first step of every job.
- Permissions default to `contents: read`; `security-events: write` is granted
  only to the CodeQL job that uploads SARIF.
- No `pull_request_target`, no `continue-on-error`.

### Tests must run, not skip

DB-backed tests skip when `AUTHKIT_TEST_DATABASE_URL` / `AUTHKIT_TEST_REDIS_URL`
are unset so a plain `go test` works offline. In CI that skip would hide a broken stack, so
`task test` / `task test-ci` export `AUTHKIT_TEST_REQUIRE_DB=1`, which turns the
skip into a failure (`internal/testdb`), and `task test-ci` fails the job if the
JSON report records any skipped test at all. Opt-in probes use build tags
(`-tags importbench`) rather than `t.Skip`.

## Running locally

```bash
task test                 # full suite against compose Postgres (task test-db-ready first)
task test-fast            # DB-free smoke
go vet ./... && go install honnef.co/go/tools/cmd/staticcheck@v0.8.1 && staticcheck ./...
go install golang.org/x/vuln/cmd/govulncheck@v1.7.0 && govulncheck ./...
```

CodeQL can be reproduced with the
[CodeQL CLI](https://docs.github.com/en/code-security/codeql-cli). Local scan
output (`.reports/`, `*.sarif`) is gitignored.

## Triage

A code-scanning finding is a lead, not a confirmed vulnerability; review it in
context. Prefer fixing root causes over suppressing rules, and note why in the
change when a suppression is unavoidable.
