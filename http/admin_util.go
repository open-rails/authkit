package authhttp

// The legacy global-roles "admin" check (IsAdmin / IsAdminInSchema /
// HasRoleDBCheck / RequireAdmin) was REMOVED in #95: the global-roles plane is
// gone, replaced by Layer-2 platform RBAC. Admin authority is now a `platform:`
// permission checked via requirePlatformPermission (see http/platform_handlers.go
// and the /admin/* routes); there is no global-admin role or DB role-flag check.
