-- Provider-link queries (core/service.go).

-- name: UserProvidersCount :one
SELECT count(*) FROM profiles.user_providers WHERE user_id = $1;

-- name: UserHasPassword :one
SELECT EXISTS(SELECT 1 FROM profiles.user_passwords WHERE user_id = $1);

-- name: UserProviderDeleteBySlug :exec
DELETE FROM profiles.user_providers WHERE user_id = $1 AND provider_slug = $2;

-- name: UserProviderDeleteOtherSubjects :exec
DELETE FROM profiles.user_providers WHERE user_id = $1 AND issuer = $2 AND subject != $3;

-- name: UserProviderUpsertByIssuer :exec
INSERT INTO profiles.user_providers (id, user_id, issuer, provider_slug, subject, email_at_provider)
VALUES ($1, $2, $3, $4, $5, $6)
ON CONFLICT (issuer, subject) DO UPDATE
SET email_at_provider = EXCLUDED.email_at_provider,
    provider_slug = COALESCE(EXCLUDED.provider_slug, profiles.user_providers.provider_slug);

-- name: ProviderLinkByIssuer :one
SELECT user_id, email_at_provider FROM profiles.user_providers WHERE issuer = $1 AND subject = $2;

-- name: ProviderLinkBySlug :one
SELECT user_id, email_at_provider FROM profiles.user_providers WHERE provider_slug = $1 AND subject = $2;

-- name: UserProviderInsertSimple :exec
INSERT INTO profiles.user_providers (id, user_id, issuer, subject, email_at_provider)
VALUES ($1, $2, $3, $4, $5)
ON CONFLICT (issuer, subject) DO UPDATE SET email_at_provider = EXCLUDED.email_at_provider;

-- name: UserProviderSetUsername :exec
UPDATE profiles.user_providers SET profile = jsonb_build_object('username', sqlc.arg(username)::text)
WHERE user_id = $1 AND issuer = $2 AND subject = $3;

-- name: UserProviderUsername :one
SELECT profile->>'username' AS username
FROM profiles.user_providers
WHERE user_id = $1 AND provider_slug = $2
ORDER BY created_at DESC LIMIT 1;

-- name: UserProviderMergeProfile :exec
UPDATE profiles.user_providers
SET profile = COALESCE(profile, '{}'::jsonb) || sqlc.arg(patch)::jsonb
WHERE user_id = $1 AND issuer = $2 AND subject = $3;

-- name: UserProviderSubjectProfileByIssuer :one
SELECT subject, created_at, COALESCE(profile, '{}'::jsonb)::text AS profile
FROM profiles.user_providers
WHERE user_id = $1 AND issuer = $2;

-- name: UserProviderSubjectByIssuer :one
SELECT subject FROM profiles.user_providers
WHERE user_id = $1 AND issuer = $2;

-- HTTP-layer provider lookups (http/reauth.go, http/user_me_get.go).

-- name: UserProviderLinkExists :one
SELECT EXISTS (
  SELECT 1
  FROM profiles.user_providers
  WHERE user_id = sqlc.arg(user_id)::uuid
    AND issuer = $2
    AND provider_slug = $3
);

-- name: UserProviderSlugsDistinct :many
SELECT DISTINCT provider_slug::text AS provider_slug
FROM profiles.user_providers
WHERE user_id = sqlc.arg(user_id)::uuid
  AND provider_slug IS NOT NULL
ORDER BY provider_slug;

-- name: UserProviderSlugs :many
SELECT provider_slug::text AS provider_slug
FROM profiles.user_providers
WHERE user_id = $1 AND provider_slug IS NOT NULL;
