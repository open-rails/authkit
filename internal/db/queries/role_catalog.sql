-- The role catalog the credential sweep last reconciled.

-- name: RoleCatalogFingerprint :one
SELECT fingerprint FROM role_catalog_state;

-- name: RoleCatalogSetFingerprint :exec
INSERT INTO role_catalog_state (fingerprint) VALUES (sqlc.arg(fingerprint))
ON CONFLICT (singleton) DO UPDATE SET fingerprint = EXCLUDED.fingerprint, swept_at = now();
