# Compatibility checks

`scripts/check-compatibility.sh [release-or-commit]` compares the current source
with an explicit baseline. Before v1, `base-ref` is a reviewed candidate; the
owner's hard cut permits updating it while the contract is being finalized.
The v1 release must replace it with the released tag, and later releases compare
against the last supported release. Updating a candidate does not declare v1.

The script rejects changed/removed published migrations and additions below the
baseline's final number. It uses Go's pinned `apidiff` to compare exported APIs
of the root and both adapter modules, then compiles each module's tests/examples
with `GOWORK=off`. Adapter requirements must resolve through their published
Go module versions; a workspace replacement cannot conceal incompatible pins.

The Go comparison deliberately flags more exported surface than the documented
host contract. A helper-only diagnostic still needs review; it does not silently
expand the semantic-versioning promise. The documented host workflows, route
table, error catalog, wire assertions and real browser workflow remain separate
obligations. API compatibility alone does not prove authorization correctness.

Reports and the immutable baseline source archive are retained under
`.reports/compatibility/<commit>`. The tool is run at an explicit version and is
not added to the library's dependency graph.
