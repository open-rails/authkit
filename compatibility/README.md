# Compatibility checks

`scripts/check-compatibility.sh [release-or-commit]` compares the current source
with an explicit baseline. Before v1, `base-ref` is a reviewed candidate; the
owner's hard cut permits updating it while the contract is being finalized.
The v1 release must replace it with the released tag, and later releases compare
against the last supported release. Updating a candidate does not declare v1.

The script rejects changed/removed published migrations and additions below the
baseline's final number, removed/changed route rows, and weakening of published
wire fixtures. New routes and additive wire fields are allowed. It uses Go's pinned `apidiff` to compare exported APIs
of the root and both adapter modules, then compiles each module's tests/examples
with `GOWORK=off`. Adapter requirements must resolve through their published
Go module versions; a workspace replacement cannot conceal incompatible pins.

The Go comparison deliberately flags more exported surface than the documented
host contract. A helper-only diagnostic still needs review; it does not silently
expand the semantic-versioning promise. The documented host workflows, route
table, error catalog, wire assertions and real browser workflow remain separate
obligations. API compatibility alone does not prove authorization correctness.

Before the first release containing these fixtures, there is no historical wire
fixture to compare with. The current workflow tests still enforce the candidate
shapes; historical preservation starts with that release. New catalog codes
extend the code/status fixture. Existing values and published route rows cannot
be changed by updating the current expectations alone.

Reports and the immutable baseline source archive are retained under
`.reports/compatibility/<commit>`. The tool is run at an explicit version and is
not added to the library's dependency graph.

Qualification on the pre-v1 candidate deliberately removed `Client.CheckSMSHealth`,
renamed `access_token` in the actual response DTO, renamed the signed JWT's `aud`
claim and edited the baseline SQL. Each check failed at the expected contract.
An additive exported constant and correctly linked next migration passed. The
temporary faults were removed. Logs are recorded with tracker #361; these are
checks of the gate itself in addition to the full PostgreSQL/Redis/browser suite.
