# Explicit group persona migration

`Client.MigrateGroupPersona` is a native host maintenance operation. It is not
an HTTP administration endpoint or a startup hook. It changes one existing
group's persona and its explicitly mapped role references while retaining the
group ID, tenant ownership, account assignments, credential IDs and secrets.
Historical native-user assignments must already belong to the group's tenant;
foreign assignments are refused, never removed or reassigned automatically.

Declare both old and new personas and roles during the maintenance window.
Quiesce incompatible writers and deploy this compatible catalog to every
credential issuer first. Removing the old catalog before migrating can make
ordinary credential reconciliation revoke the old credentials.
Nonempty `catalog_issuer` references must match this client's configured
issuer. A different issuer may give the same role name a different meaning;
the operation reports those issuers and refuses, including an already-target
validation. Inspecting ordinary group metadata remains available separately.

Build an `iam.GroupPersonaMigration` with the exact group, source and target
personas, a one-to-one role map and a one-to-one concrete permission map. No
wildcard prefix replacement or same-name owner mapping is inferred. Each
mapped role must retain exactly its translated concrete grants and MFA
requirements. Existing custom definitions must remain custom; an explicitly
named target custom role can also preserve a former declared role as a fixed
set of concrete grants. The target must support the group's existing API keys,
remote applications and OAuth clients.

Call with `Apply: false` (the default), inspect the report, and save its
`Fingerprint`. The dry-run uses a read-only, repeatable-read snapshot. It
reports counts, role changes, credential issuers and token reissue needs; it
contains no credential material or account contact details.

Apply the same plan with `Apply: true` and `ExpectedFingerprint` set to the
reviewed value. Changed bindings, maps, catalogs or credential-issuer grants
refuse the apply. The operation requires table-owner privileges and briefly
takes an exclusive lock on the permission-group table after the shared
authority lock. It temporarily disables only the ordinary persona-identity
trigger, reenables it before commit, and leaves tenant-ownership guards active.
Every failure rolls back both data and trigger state. Ordinary group updates
remain unable to change a persona afterward.

The operation updates role references in account and remote-user assignments,
remote-application assignments and role maps, API keys, invitation links,
registration invitations, and custom role definitions. It retains OAuth client
and consent identities. Historical account events are not rewritten. One
`group.persona_migrated` event records a successful transition in its own
transaction; dry-runs, retries already at the target, and rollbacks emit none.
A retained
delegated credential's issuer must still cover its translated role; the migration refuses
instead of silently revoking that credential. Keep the returned report with
the host's maintenance audit.
Organization API keys retain their translated group role independently of the
creator's current grants; the role must still be valid and suitable for a machine.

Signed tokens may carry old permission ceilings. Their claims are never
rewritten or broadened; refresh or reissue them as indicated by the report.
An already-target group is accepted only when its current references and
definitions match the explicit maps, and returns `AlreadyTarget: true` without
writing again.

Root cannot be a source or target. A canonical tenant group cannot be relabeled
away from `tenant`; migration into `tenant` requires its group ID to equal its
tenant ID. A tenant-bound client cannot migrate another tenant's group. A
legacy content-only owner must not be mapped to a broader tenant owner: declare
or explicitly name a limited compatibility role retaining only the old mapped
grants, or the migration refuses it.
