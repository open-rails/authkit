-- Group OAuth clients (#450) and users' consents to them.

-- name: GroupOAuthClientInsert :one
INSERT INTO group_oauth_clients (client_id, permission_group_id, client_name, logo_uri, client_uri, policy_uri, tos_uri,
    redirect_uris, post_logout_redirect_uris, token_endpoint_auth_method, secret_hash, jwks_uri, scopes, backchannel_logout_uri)
VALUES (sqlc.arg(client_id), sqlc.arg(group_id)::uuid, sqlc.arg(client_name), sqlc.narg(logo_uri), sqlc.narg(client_uri),
    sqlc.narg(policy_uri), sqlc.narg(tos_uri), sqlc.arg(redirect_uris)::text[], sqlc.arg(post_logout_redirect_uris)::text[],
    sqlc.arg(token_endpoint_auth_method), sqlc.narg(secret_hash), sqlc.narg(jwks_uri), sqlc.arg(scopes)::text[], sqlc.narg(backchannel_logout_uri))
RETURNING *;

-- name: GroupOAuthClientCount :one
SELECT count(*) FROM group_oauth_clients WHERE permission_group_id = sqlc.arg(group_id)::uuid;

-- name: GroupOAuthClientsByGroup :many
SELECT * FROM group_oauth_clients WHERE permission_group_id = sqlc.arg(group_id)::uuid
ORDER BY created_at, client_id;

-- name: GroupOAuthClientInGroup :one
SELECT * FROM group_oauth_clients WHERE client_id = sqlc.arg(client_id) AND permission_group_id = sqlc.arg(group_id)::uuid;

-- name: GroupOAuthClientLive :one
-- A client of a live group, enabled: the one the authorization server and
-- resource server accept.
SELECT c.* FROM group_oauth_clients c
JOIN permission_groups g ON g.id = c.permission_group_id
WHERE c.client_id = sqlc.arg(client_id) AND c.disabled_at IS NULL AND g.deleted_at IS NULL;

-- name: GroupOAuthClientUpdate :one
UPDATE group_oauth_clients SET
    client_name = sqlc.arg(client_name), logo_uri = sqlc.narg(logo_uri), client_uri = sqlc.narg(client_uri),
    policy_uri = sqlc.narg(policy_uri), tos_uri = sqlc.narg(tos_uri), redirect_uris = sqlc.arg(redirect_uris)::text[],
    post_logout_redirect_uris = sqlc.arg(post_logout_redirect_uris)::text[], jwks_uri = sqlc.narg(jwks_uri),
    scopes = sqlc.arg(scopes)::text[], backchannel_logout_uri = sqlc.narg(backchannel_logout_uri),
    disabled_at = CASE WHEN sqlc.arg(disabled)::boolean THEN coalesce(disabled_at, now()) END,
    updated_at = now()
WHERE client_id = sqlc.arg(client_id) AND permission_group_id = sqlc.arg(group_id)::uuid
RETURNING *;

-- name: GroupOAuthClientSetSecret :execrows
UPDATE group_oauth_clients SET secret_hash = sqlc.arg(secret_hash), updated_at = now()
WHERE client_id = sqlc.arg(client_id) AND permission_group_id = sqlc.arg(group_id)::uuid
  AND token_endpoint_auth_method = 'client_secret_basic';

-- name: GroupOAuthClientDelete :execrows
DELETE FROM group_oauth_clients WHERE client_id = sqlc.arg(client_id) AND permission_group_id = sqlc.arg(group_id)::uuid;

-- name: GroupOAuthClientRedirectOrigin :one
-- Whether a live, enabled client redirects to origin: one a browser client
-- calls the token endpoint from.
SELECT EXISTS (
    SELECT 1 FROM group_oauth_clients c
    JOIN permission_groups g ON g.id = c.permission_group_id
    CROSS JOIN LATERAL unnest(c.redirect_uris) AS u(uri)
    WHERE c.disabled_at IS NULL AND g.deleted_at IS NULL
      AND (u.uri = sqlc.arg(origin)::text OR starts_with(u.uri, sqlc.arg(origin)::text || '/'))
)::boolean;

-- name: OAuthConsentByUserClient :one
SELECT scopes, granted_at, updated_at FROM oauth_consents
WHERE user_id = sqlc.arg(user_id)::uuid AND client_id = sqlc.arg(client_id);

-- name: OAuthConsentGrant :one
-- Adds scopes to the user's consent, creating it.
INSERT INTO oauth_consents (user_id, client_id, scopes)
VALUES (sqlc.arg(user_id)::uuid, sqlc.arg(client_id), sqlc.arg(scopes)::text[])
ON CONFLICT (user_id, client_id) DO UPDATE SET
    scopes = ARRAY(SELECT DISTINCT s FROM unnest(oauth_consents.scopes || EXCLUDED.scopes) AS s ORDER BY s),
    updated_at = now()
RETURNING scopes, granted_at, updated_at;

-- name: OAuthConsentDelete :one
DELETE FROM oauth_consents WHERE user_id = sqlc.arg(user_id)::uuid AND client_id = sqlc.arg(client_id)
RETURNING granted_at;

-- name: OAuthConsentsByUser :many
SELECT oc.client_id, oc.scopes, oc.granted_at, oc.updated_at,
    c.client_name, c.permission_group_id::text AS group_id, c.logo_uri, c.client_uri
FROM oauth_consents oc
JOIN group_oauth_clients c ON c.client_id = oc.client_id
WHERE oc.user_id = sqlc.arg(user_id)::uuid
ORDER BY oc.updated_at DESC, oc.client_id;

-- name: GroupOAuthClientByID :one
SELECT * FROM group_oauth_clients WHERE client_id = sqlc.arg(client_id);
