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

The `Validate` workflow in `.github/workflows/ci.yaml` runs on pushes and pull
requests to `master`, and through `workflow_dispatch`. It has three jobs:

| Job | Checks |
|---|---|
| `workflows` | Race-tested AuthKit and adapter workflows against PostgreSQL 18 and Redis, the adversarial `securitytest` suite ([threat map](docs/security-tests.md)), then the two-site Chrome cookie workflow. The event gate requires the retained workflows and every security test to pass with no skipped tests. |
| `contracts` | Go vet, SQLC generation/vet and generated-code drift, published migration/route/wire/API contracts, and module-isolated adapter checks. Fiber additionally runs its race suite and vet against the published root dependency. |
| `Required Security` | Pinned govulncheck for reachable dependency vulnerabilities, plus a Trivy filesystem scan for fixable HIGH/CRITICAL dependency, secret and configuration findings. |

Permissions default to `contents: read`. Actions and installed tools carry
explicit version or commit pins. Dependabot proposes weekly updates for the
root and all adapter Go modules and GitHub Actions; updates use the same checks.
No job uses `pull_request_target` or `continue-on-error`.

### Tests must run, not skip

Ordinary offline `go test` may skip database-backed tests when their service
URLs are absent. `scripts/check.sh` supplies the PostgreSQL/Redis configuration
and sets `AUTHKIT_TEST_REQUIRE_DB=1`, turning missing database configuration
into a failure. Its workflow event gate also rejects skipped tests or missing
required workflow passes.

## Running locally

```bash
pnpm --dir authhttp/testdata install --frozen-lockfile
pnpm --dir authhttp/testdata exec playwright install --with-deps chromium
scripts/check.sh all       # workflows and contracts; starts local compose services if needed
scripts/check.sh contracts # contracts only

go install golang.org/x/vuln/cmd/govulncheck@v1.7.0
govulncheck ./...
```

Set `AUTHKIT_TEST_DATABASE_URL` and `AUTHKIT_TEST_REDIS_URL` to use existing
local services. `.reports/` is gitignored. Published-module verification uses
`GOWORK=off` and rejects module replacements; see [compatibility checks](compatibility/README.md).

## Triage

A code-scanning finding is a lead, not a confirmed vulnerability; review it in
context. Prefer fixing root causes over suppressing rules, and note why in the
change when a suppression is unavoidable.
