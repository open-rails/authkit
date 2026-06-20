# Migration: v0.13.0 — remove the global `TenantMode` (issue #60)

**Breaking.** AuthKit no longer has a global `single`/`multi` tenant mode. Tenants
are **always** a supported primitive at the core/library layer; what a host
*exposes* is now decided by route-group mounting + the two registration modes,
not by a mode flag.

## What changed

- Removed `core.Config.TenantMode` and `core.Options.TenantMode` (and the
  `"single"` default + validation). Setting it is a compile error now.
- `WithTenantMode(...)` (verifier option) is a **deprecated no-op shim** — kept so
  callers still compile; delete the call at your convenience. Tenant claims are
  parsed whenever present.
- `AutoCreatePersonalTenants` is now a **direct opt-in** (no longer gated on
  `TenantMode == "multi"`).
- Tenant routes are **always registered** under the `RouteTenants` group; expose
  them by mounting that group. Mutating routes stay gated by
  `TenantRegistrationMode`. The `/password/login` + `/token` `tenant_not_supported`
  rejection is gone — a `tenant` param is accepted and follows membership handling.
- Token claims are uniform: a user access token always carries `global_roles` and
  a legacy `roles` claim mirroring it; tenant-scoped tokens additionally carry
  `tenant` + tenant roles. (Previously `roles` was single-mode only.)
- `IssueOrgAccessToken` / refresh-with-org are membership-gated, not mode-gated.
- Removed the `WithPostgres` multi→single downgrade panic.

## Consumer steps

1. `go get github.com/open-rails/authkit@v0.13.0`.
2. Delete any `TenantMode:` field from `core.Config`/`core.Options` literals.
3. Delete `WithTenantMode(...)` calls (optional — it's a no-op now).
4. Decide exposure explicitly:
   - **Public registration** → set `NativeUserRegistrationMode` / `TenantRegistrationMode` to `open` and mount the relevant route groups.
   - **Closed / self-hosted** → leave registration modes closed (default) and mount only the route groups you intend to expose.
   - **Personal workspaces** → set `AutoCreatePersonalTenants: true`.

## Per-host posture (reference)

- **OpenRails (self-hosted, closed):** no public user/tenant registration; tenants
  come from manifests/bootstrap; mounts the intentional (non-DefaultAPI) groups.
  Adopted in openrails by dropping the `TenantMode` set; registration is now
  controlled by `public_user_registration` + `public_tenant_registration`
  (default false). The derived self-hosted posture replaces the old `locked_down`.
- **OpenRails SaaS:** expose user signup + user-owned tenant creation
  (`NativeUserRegistrationMode = open`, `TenantRegistrationMode = open`, mount the
  tenants group).
- **Doujins / Hentai0:** expose user signup but NOT public tenant registration
  (`NativeUserRegistrationMode = open`, `TenantRegistrationMode` closed).
- **Tensorhub:** embedded/bootstrap use only — no public registration; dropped its
  `TenantMode: "multi"` field-sets; tenants resolved by the host.
