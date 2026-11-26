# Open release candidate

`rc/1.58.0`: one migration baseline. AuthKit's migrations fold into one hand-written `0001_schema.up.sql` and the paths kept for older databases go; every AuthKit database is rebuilt.

One RC is open at a time. This file names its branch (`rc/<version>`, the version it will become, cut from master) and what it is for; feature PRs target that branch. See [branches and CI](docs/ci.md).
