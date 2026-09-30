-- Each app's role catalog as its credential sweep last reconciled it, and the
-- fleets that sweep the credentials of the other apps sharing the accounts.

-- name: RoleCatalogFingerprint :one
SELECT fingerprint FROM role_catalogs WHERE issuer = sqlc.arg(issuer);

-- name: RoleCatalogSet :exec
INSERT INTO role_catalogs (issuer, fingerprint, roles) VALUES (sqlc.arg(issuer), sqlc.arg(fingerprint), sqlc.arg(roles)::text[])
ON CONFLICT (issuer) DO UPDATE SET fingerprint = EXCLUDED.fingerprint, roles = EXCLUDED.roles, swept_at = now();

-- name: RoleCatalogsDeclaredRoles :many
-- The persona:role names the catalogs of issuers declare.
SELECT DISTINCT unnest(roles)::text AS role FROM role_catalogs WHERE issuer = ANY(sqlc.arg(issuers)::text[]);

-- name: CredentialSweepFleetsForShare :many
-- The fleets of issuers, key-share locked until the change commits.
SELECT issuer, river_schema FROM account_delivery_fleets
WHERE issuer = ANY(sqlc.arg(issuers)::text[])
ORDER BY issuer FOR KEY SHARE;
