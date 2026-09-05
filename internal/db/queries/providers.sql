-- Provider-link queries (core/service.go).

-- name: UserProvidersCount :one
SELECT count(*) FROM profiles.user_providers WHERE user_id = $1 AND verified_at IS NOT NULL;

-- name: UserProviderCountForUpdate :one
-- Locks the user's provider rows (FOR UPDATE in the inner query) and returns the
-- count, so a concurrent unlink for the same user serializes behind this lock —
-- closing the last-credential TOCTOU. Must run inside a transaction.
SELECT count(*)::int AS n FROM (
  SELECT 1 FROM profiles.user_providers
  WHERE user_id = sqlc.arg(user_id)::uuid AND verified_at IS NOT NULL
  FOR UPDATE
) locked;

-- name: UserHasPassword :one
SELECT EXISTS(SELECT 1 FROM profiles.user_passwords WHERE user_id = $1);

-- name: UserProviderDeleteBySlug :exec
DELETE FROM profiles.user_providers WHERE user_id = $1 AND provider_slug = $2;

-- name: UserProviderUpsertByIssuer :one
INSERT INTO profiles.user_providers (id, user_id, issuer, provider_slug, subject, email_at_provider)
VALUES ($1, $2, $3, $4, $5, $6)
ON CONFLICT (issuer, subject) DO UPDATE
SET email_at_provider = EXCLUDED.email_at_provider,
    provider_slug = COALESCE(EXCLUDED.provider_slug, profiles.user_providers.provider_slug)
WHERE profiles.user_providers.user_id = EXCLUDED.user_id
RETURNING id, user_id, verified_at;

-- name: ProviderLinkByIssuer :one
SELECT user_id, email_at_provider
FROM profiles.user_providers
WHERE issuer = $1 AND subject = $2 AND verified_at IS NOT NULL;

-- name: UserProviderSetUsername :exec
UPDATE profiles.user_providers SET profile = jsonb_build_object('username', sqlc.arg(username)::text)
WHERE user_id = $1 AND issuer = $2 AND subject = $3 AND verified_at IS NOT NULL;

-- name: UserProviderMergeProfile :exec
UPDATE profiles.user_providers
SET profile = COALESCE(profile, '{}'::jsonb) || sqlc.arg(patch)::jsonb
WHERE user_id = $1 AND issuer = $2 AND subject = $3 AND verified_at IS NOT NULL;

-- name: UserProviderSubjectProfileByIssuer :one
SELECT subject, created_at, verified_at, COALESCE(profile, '{}'::jsonb)::text AS profile
FROM profiles.user_providers
WHERE user_id = $1 AND issuer = $2;

-- HTTP-layer provider lookups (http/step_up.go, http/user_me_get.go).

-- name: UserProviderLinkExists :one
SELECT EXISTS (
  SELECT 1
  FROM profiles.user_providers
  WHERE user_id = sqlc.arg(user_id)::uuid
    AND issuer = $2
    AND provider_slug = $3
    AND verified_at IS NOT NULL
);

-- name: UserProviderSlugsDistinct :many
SELECT DISTINCT provider_slug::text AS provider_slug
FROM profiles.user_providers
WHERE user_id = sqlc.arg(user_id)::uuid
  AND provider_slug IS NOT NULL
  AND verified_at IS NOT NULL
ORDER BY provider_slug;

-- name: UserProviderSlugs :many
SELECT provider_slug::text AS provider_slug
FROM profiles.user_providers
WHERE user_id = $1 AND provider_slug IS NOT NULL AND verified_at IS NOT NULL;
