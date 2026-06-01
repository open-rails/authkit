### Security

Security policy and static analysis (SAST) setup for AuthKit.

AuthKit is an auth library, so the code it ships runs inside other people's
trust boundaries. To keep the signal high we lean on a small, Go-focused set of
scanners that run in CI on every push and pull request, plus a weekly scheduled
sweep. Findings are uploaded as SARIF to GitHub code scanning (Security tab),
not gated as hard CI failures, so contributors see issues without being blocked
on noisy or low-confidence hits.

Reporting a vulnerability
- Please do not open public issues for security problems.
- Report privately via GitHub Security Advisories ("Report a vulnerability" on
  the repo Security tab), or contact the maintainers directly.
- Include affected version/commit, a reproduction or PoC if possible, and the
  impact you observed. We aim to acknowledge reports promptly and coordinate a
  fix and disclosure timeline with you.

---

Scope (minimal)
- gosec: Go security-focused SAST (crypto, randomness, SQL, file perms, command injection, hardcoded creds).
- go vet + staticcheck: correctness and suspicious-construct analysis.
- CodeQL (Go): dataflow/taint analysis with the `security-extended` and `security-and-quality` query suites.

Everything else (secret scanning, dependency/supply-chain, container, Semgrep)
is intentionally out of scope here to keep this a Go SAST baseline.

---

Workflows

Two GitHub Actions workflows live in `.github/workflows/`:

- `go-sast.yml` — runs `gosec` and `staticcheck + go vet` as separate jobs.
- `codeql.yml` — runs CodeQL analysis for Go.

Both trigger on:
- `push` to `master`/`main`
- `pull_request` targeting `master`/`main`
- a weekly schedule (Monday, `go-sast` 06:00 UTC, `codeql` 07:00 UTC)
- `workflow_dispatch` (manual run)

Runners are pinned to commit SHAs and hardened with `step-security/harden-runner`
(egress audit). Permissions default to `contents: read`, with `security-events:
write` granted only to the jobs that upload SARIF.

---

gosec configuration

Rule tuning lives in `.gosec.json` (gosec's `-conf` flag only reads JSON, not
YAML). The config sets global options and the G101 hardcoded-credentials
pattern:

```json
{
  "global": {
    "audit": "enabled",
    "nosec": "enabled",
    "show-ignored": "true"
  },
  "G101": {
    "pattern": "(?i)(passwd|pass|password|pwd|secret|token|api_key|apikey|access_key|auth)",
    "ignore_entropy": false
  }
}
```

Severity/confidence thresholds, rule exclusions, and directory exclusions are
gosec CLI flags (they are not valid config-file fields), so they are passed in
the workflow:

- `-severity medium -confidence medium` — report medium and above.
- `-exclude=G104` — unhandled errors are covered by staticcheck/`errcheck`-style
  analysis instead, so they are suppressed here to cut noise.
- `-exclude-dir=testing -exclude-dir=migrations -exclude-dir=agents` — skip
  generated/test fixtures.

---

Running locally

gosec (matches the CI invocation):

```bash
go install github.com/securego/gosec/v2/cmd/gosec@v2.22.10

gosec \
  -fmt sarif -out gosec.sarif \
  -conf .gosec.json \
  -severity medium -confidence medium -exclude=G104 \
  -exclude-dir=testing -exclude-dir=migrations -exclude-dir=agents \
  ./...
```

go vet + staticcheck:

```bash
go vet ./...
go install honnef.co/go/tools/cmd/staticcheck@latest
staticcheck ./...
```

CodeQL is normally only run in CI, but can be reproduced locally with the
[CodeQL CLI](https://docs.github.com/en/code-security/codeql-cli) if needed.

Local scan output (`.reports/`, `*.sarif`) is gitignored. With the medium
severity/confidence threshold and G104 excluded, a full gosec run currently
reports a small handful of findings rather than the raw ~180 it produces with
no tuning.

---

Triage notes
- A finding in code scanning is a lead, not a confirmed vulnerability — review
  each in context before acting.
- To suppress an intentional, reviewed gosec finding inline, annotate the line
  with `// #nosec Gxxx -- <reason>`. Use sparingly and always with a reason.
- Prefer fixing root causes over excluding rules. If a rule is consistently
  wrong for this codebase, adjust `.gosec.json` or the workflow flags and note
  why in the change.
