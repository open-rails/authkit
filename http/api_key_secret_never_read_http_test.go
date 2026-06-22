package authhttp

import (
	"context"
	"crypto"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	core "github.com/open-rails/authkit/core"
	jwtkit "github.com/open-rails/authkit/jwt"
	"github.com/stretchr/testify/require"
)

// TestAPIKeySecretNeverReturnedByReadHTTP proves the #95 invariant "secrets never
// returned by any read." An API key's plaintext secret/token is returned EXACTLY
// once — in the mint (POST /orgs/{org}/api-keys) response `token` field — and is
// NEVER retrievable again by any read. This asserts:
//   - The mint response carries a `token` (the one-time plaintext).
//   - GET /orgs/{org}/api-keys (the list read — the only read surface; there is
//     no single-key GET route) NEVER contains that plaintext, nor ANY field whose
//     name suggests a secret (token / secret / hash / plaintext), at any depth.
//   - The list returns only the non-secret view: id, key_id, name, permissions,
//     resources, timestamps.
//   - The secret_hash column (DB-only) is never serialized.
//
// Skips without AUTHKIT_TEST_DATABASE_URL.
func TestAPIKeySecretNeverReturnedByReadHTTP(t *testing.T) {
	pool := remoteApplicationBoundaryPG(t)
	ctx := context.Background()
	prefix := fmt.Sprintf("apikey-secret-%d", time.Now().UnixNano())

	signer, err := jwtkit.NewRSASigner(2048, "apikey-secret")
	require.NoError(t, err)
	coreSvc := core.NewService(core.Options{
		Issuer:                   "https://" + prefix + ".authkit.test",
		IssuedAudiences:          []string{"plat"},
		ExpectedAudiences:        []string{"plat"},
		AccessTokenDuration:      time.Hour,
		RegistrationVerification: core.RegistrationVerificationNone,
		APIKeyPrefix:             "authkit",
	}, core.Keyset{
		Active:     signer,
		PublicKeys: map[string]crypto.PublicKey{signer.KID(): signer.PublicKey()},
	}, core.WithPostgres(pool))
	verifier := NewVerifier(WithSkew(5 * time.Second)).WithService(coreSvc)
	require.NoError(t, verifier.AddIssuer(coreSvc.Options().Issuer, coreSvc.Options().ExpectedAudiences, IssuerOptions{
		RawKeys: coreSvc.PublicKeysByKID(),
	}))
	svc := &Service{svc: coreSvc, verifier: verifier}
	server := httptest.NewServer(svc.APIHandler())
	t.Cleanup(server.Close)

	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM profiles.orgs WHERE slug LIKE $1`, prefix+"%")
		_, _ = pool.Exec(context.Background(), `DELETE FROM profiles.users WHERE username LIKE $1`, prefix+"%")
	})

	owner := createBoundaryUser(t, ctx, coreSvc, prefix+"-owner")
	org, err := coreSvc.CreateOrgForUser(ctx, core.CreateOrgForUserRequest{Slug: prefix + "-org", OwnerUserID: owner.ID})
	require.NoError(t, err)
	ownerTok := issueBoundaryUserToken(t, ctx, coreSvc, owner)
	req := func(method, path string, body any) (int, string) {
		return remoteApplicationBoundaryRequestPath(t, server.URL, path, method, ownerTok, body)
	}

	base := "/orgs/" + org.Slug + "/api-keys"

	// An API key holds exactly ONE org ROLE (#95). Define a read-only "auditor"
	// role conferring org:members:read — a catalog perm the owner holds (org:*) and
	// grantable to an API key (read-only, escalation-harmless).
	require.NoError(t, coreSvc.DefineRole(ctx, org.Slug, "auditor"))
	require.NoError(t, coreSvc.SetRolePermissions(ctx, org.Slug, "auditor", []string{core.PermOrgMembersRead}))

	// Mint an API key over HTTP and capture the one-time plaintext `token`.
	status, body := req(http.MethodPost, base, map[string]any{
		"name": prefix + "-ci",
		"role": "auditor",
	})
	require.Equal(t, http.StatusCreated, status, body)

	var mintResp map[string]any
	require.NoError(t, json.Unmarshal([]byte(body), &mintResp))
	plaintext, ok := mintResp["token"].(string)
	require.True(t, ok, "mint response must carry the one-time plaintext token: %s", body)
	require.NotEmpty(t, plaintext)
	keyID, _ := mintResp["key_id"].(string)
	require.NotEmpty(t, keyID, "mint response must carry key_id: %s", body)
	// The plaintext is NOT merely the key_id (which IS readable) — it carries the
	// secret portion, so a leak would be a real exposure.
	require.NotEqual(t, keyID, plaintext)

	// The list read — the ONLY read surface for API keys (no single-key GET route
	// exists). It must NOT contain the plaintext, nor any secret-named field.
	status, listBody := req(http.MethodGet, base, nil)
	require.Equal(t, http.StatusOK, status, listBody)

	// 1. The exact one-time plaintext secret must NOT appear anywhere in the read.
	require.NotContains(t, listBody, plaintext, "the plaintext API-key token must NEVER be returned by a read")

	// 2. No field at any depth may be named token/secret/hash/plaintext, and the
	//    only string values present must be the non-secret view fields.
	var listResp map[string]any
	require.NoError(t, json.Unmarshal([]byte(listBody), &listResp))
	keys, ok := listResp["api_keys"].([]any)
	require.True(t, ok, "list response must carry api_keys: %s", listBody)
	require.NotEmpty(t, keys, "the minted key must appear in the list")

	allowed := map[string]bool{
		"id": true, "key_id": true, "name": true, "role": true, "permissions": true,
		"resources": true, "created_by": true, "created_at": true,
		"last_used_at": true, "expires_at": true, "revoked_at": true,
		// resource entries:
		"kind": true,
	}
	assertNoSecretFields(t, listResp, allowed)

	// 3. Defense-in-depth: the secret_hash column truly exists in the DB for this
	//    key (so the read genuinely had something to hide), yet the marshalled read
	//    leaks neither the hash nor any "hash"/"secret" substring.
	// The API-key credential is persisted in profiles.service_tokens (the table
	// retained its legacy name; the secret_hash column is DB-only, never modeled
	// on the core.APIKey domain struct).
	var hashLen int
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT octet_length(k.secret_hash) FROM profiles.service_tokens k JOIN profiles.orgs o ON o.id = k.org_id WHERE o.slug = $1`,
		org.Slug).Scan(&hashLen))
	require.Positive(t, hashLen, "the api key must have a stored secret_hash")
	lower := strings.ToLower(listBody)
	require.NotContains(t, lower, "secret_hash")
	require.NotContains(t, lower, "\"hash\"")
	require.NotContains(t, lower, "\"secret\"")
}

// assertNoSecretFields walks a decoded JSON value and fails if any object key is
// not in the allow-list (catching a newly-serialized secret field by construction)
// or names a secret (token/secret/hash/plaintext/password).
func assertNoSecretFields(t *testing.T, v any, allowed map[string]bool) {
	t.Helper()
	switch node := v.(type) {
	case map[string]any:
		for k, child := range node {
			if k == "api_keys" { // the list wrapper key
				assertNoSecretFields(t, child, allowed)
				continue
			}
			lk := strings.ToLower(k)
			for _, banned := range []string{"token", "secret", "hash", "plaintext", "password"} {
				require.NotContainsf(t, lk, banned, "a read response must not serialize a %q-named field (found %q)", banned, k)
			}
			require.Truef(t, allowed[k], "unexpected field %q in API-key read view — only the non-secret view is allowed", k)
			assertNoSecretFields(t, child, allowed)
		}
	case []any:
		for _, child := range node {
			assertNoSecretFields(t, child, allowed)
		}
	}
}
