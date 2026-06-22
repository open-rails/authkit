package authhttp

import (
	"bytes"
	"context"
	"crypto"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	core "github.com/open-rails/authkit/core"
	jwtkit "github.com/open-rails/authkit/jwt"
	"github.com/stretchr/testify/require"
)

func TestRemoteApplicationHTTPOrgBoundary(t *testing.T) {
	pool := remoteApplicationBoundaryPG(t)
	ctx := context.Background()
	prefix := fmt.Sprintf("ra-boundary-%d", time.Now().UnixNano())

	signer, err := jwtkit.NewRSASigner(2048, "boundary-authkit")
	require.NoError(t, err)
	coreSvc := core.NewService(core.Options{
		Issuer:                   "https://" + prefix + ".authkit.test",
		IssuedAudiences:          []string{"authkit-boundary"},
		ExpectedAudiences:        []string{"authkit-boundary"},
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
		_, _ = pool.Exec(context.Background(), `DELETE FROM profiles.remote_applications WHERE slug LIKE $1 OR issuer LIKE $2`, prefix+"%", "https://"+prefix+"%")
		_, _ = pool.Exec(context.Background(), `DELETE FROM profiles.orgs WHERE slug LIKE $1`, prefix+"%")
		_, _ = pool.Exec(context.Background(), `DELETE FROM profiles.users WHERE username LIKE $1`, prefix+"%")
	})

	ownerA := createBoundaryUser(t, ctx, coreSvc, prefix+"-owner-a")
	managerA := createBoundaryUser(t, ctx, coreSvc, prefix+"-manager-a")
	viewerA := createBoundaryUser(t, ctx, coreSvc, prefix+"-viewer-a")
	ownerB := createBoundaryUser(t, ctx, coreSvc, prefix+"-owner-b")
	managerB := createBoundaryUser(t, ctx, coreSvc, prefix+"-manager-b")

	orgA, err := coreSvc.CreateOrgForUser(ctx, core.CreateOrgForUserRequest{Slug: prefix + "-org-a", OwnerUserID: ownerA.ID})
	require.NoError(t, err)
	orgB, err := coreSvc.CreateOrgForUser(ctx, core.CreateOrgForUserRequest{Slug: prefix + "-org-b", OwnerUserID: ownerB.ID})
	require.NoError(t, err)

	require.NoError(t, coreSvc.DefineRole(ctx, orgA.Slug, "remote-app-manager"))
	require.NoError(t, coreSvc.SetRolePermissions(ctx, orgA.Slug, "remote-app-manager", []string{"org:remote_applications:*"}))
	require.NoError(t, coreSvc.AddMember(ctx, orgA.Slug, managerA.ID))
	require.NoError(t, coreSvc.AssignRole(ctx, orgA.Slug, managerA.ID, "remote-app-manager"))
	require.NoError(t, coreSvc.AddMember(ctx, orgA.Slug, viewerA.ID))

	require.NoError(t, coreSvc.DefineRole(ctx, orgB.Slug, "remote-app-manager"))
	require.NoError(t, coreSvc.SetRolePermissions(ctx, orgB.Slug, "remote-app-manager", []string{"org:remote_applications:*"}))
	require.NoError(t, coreSvc.AddMember(ctx, orgB.Slug, managerB.ID))
	require.NoError(t, coreSvc.AssignRole(ctx, orgB.Slug, managerB.ID, "remote-app-manager"))

	managerAToken := issueBoundaryUserToken(t, ctx, coreSvc, managerA)
	viewerAToken := issueBoundaryUserToken(t, ctx, coreSvc, viewerA)
	managerBToken := issueBoundaryUserToken(t, ctx, coreSvc, managerB)

	issuerA := "https://" + prefix + "-app-a.example/issuer"
	// No auth → 401 (before any org gate).
	status, body := remoteApplicationBoundaryRegister(t, server.URL, orgA.Slug, "", map[string]any{
		"slug": "missing-auth", "issuer": issuerA, "jwks_uri": "https://example.com/jwks.json",
	})
	require.Equal(t, http.StatusUnauthorized, status, body)

	// managerA, body missing issuer → 400: validation runs before the DB gate.
	status, body = remoteApplicationBoundaryRegister(t, server.URL, orgA.Slug, managerAToken, map[string]any{
		"slug": prefix + "-bad", "jwks_uri": "https://example.com/jwks.json",
	})
	require.Equal(t, http.StatusBadRequest, status, body)

	// managerA registers app-a under orgA's path → 200, owned by orgA.
	status, body = remoteApplicationBoundaryRegister(t, server.URL, orgA.Slug, managerAToken, map[string]any{
		"slug": prefix + "-app-a", "issuer": issuerA, "jwks_uri": "https://example.com/jwks.json",
	})
	require.Equal(t, http.StatusOK, status, body)
	registered, err := coreSvc.GetRemoteApplication(ctx, issuerA)
	require.NoError(t, err)
	require.Equal(t, orgA.ID, registered.OrgID)

	// viewerA is a member of orgA but holds no org:remote_applications:* → 403.
	status, body = remoteApplicationBoundaryRegister(t, server.URL, orgA.Slug, viewerAToken, map[string]any{
		"slug": prefix + "-viewer", "issuer": "https://" + prefix + "-viewer.example/issuer", "jwks_uri": "https://example.com/viewer-jwks.json",
	})
	require.Equal(t, http.StatusForbidden, status, body)

	// managerB manages orgB, but issuerA is already owned by orgA. Re-registering
	// it under orgB is an anti-takeover conflict → 409 (never a silent re-bind).
	status, body = remoteApplicationBoundaryRegister(t, server.URL, orgB.Slug, managerBToken, map[string]any{
		"slug": prefix + "-app-a", "issuer": issuerA, "jwks_uri": "https://example.com/cross-jwks.json",
	})
	require.Equal(t, http.StatusConflict, status, body)

	// managerA can't register in orgB (an org it doesn't manage) → 403. The org
	// is the PATH, so there is no org-less registration at all.
	status, body = remoteApplicationBoundaryRegister(t, server.URL, orgB.Slug, managerAToken, map[string]any{
		"slug": prefix + "-cross", "issuer": "https://" + prefix + "-cross.example/issuer", "jwks_uri": "https://example.com/cross2-jwks.json",
	})
	require.Equal(t, http.StatusForbidden, status, body)

	// Bind a bootstrap issuer to orgB so managerA (orgA) can't delete it —
	// cross-org isolation on the slug-addressed delete path.
	_, err = coreSvc.UpsertRemoteApplication(ctx, core.RemoteApplication{
		Slug:    prefix + "-bootstrap",
		OrgID:   orgB.ID,
		Issuer:  "https://" + prefix + "-bootstrap.example/issuer",
		JWKSURI: "https://example.com/bootstrap-jwks.json",
		Enabled: true,
	})
	require.NoError(t, err)
	status, body = remoteApplicationBoundaryDelete(t, server.URL, orgB.Slug, prefix+"-bootstrap", managerAToken)
	require.Equal(t, http.StatusForbidden, status, body)

	// An API key holds exactly ONE org role (#95). Define a role and bind the key
	// to it; the exact perm is irrelevant to this test (the key is a machine
	// credential and must be rejected regardless).
	require.NoError(t, coreSvc.DefineRole(ctx, orgA.Slug, "remote-app-mgr"))
	require.NoError(t, coreSvc.SetRolePermissions(ctx, orgA.Slug, "remote-app-mgr", []string{core.PermOrgRemoteAppsUpdate}))
	_, servicePlaintext, err := coreSvc.MintAPIKeyWithOptions(ctx, orgA.Slug, core.APIKeyMintOptions{
		Name:      prefix + "-api-key",
		Role:      "remote-app-mgr",
		CreatedBy: ownerA.ID,
	})
	require.NoError(t, err)
	remoteAppSelfToken := mintBoundaryRemoteApplicationSelfToken(t, ctx, coreSvc, verifier, prefix, orgA)
	delegatedToken := mintBoundaryDelegatedToken(t, verifier, prefix)
	// A machine credential (API key / remote-app self / delegated) carries no
	// human UserID, so it can never mutate the trust registry → 401.
	for name, token := range map[string]string{
		"api-key":                 servicePlaintext,
		"remote-application-self": remoteAppSelfToken,
		"delegated-token":         delegatedToken,
	} {
		t.Run("rejects "+name, func(t *testing.T) {
			status, body := remoteApplicationBoundaryRegister(t, server.URL, orgA.Slug, token, map[string]any{
				"slug": prefix + "-" + name, "issuer": "https://" + prefix + "-" + name + ".example/issuer", "jwks_uri": "https://example.com/credential-jwks.json",
			})
			require.Equal(t, http.StatusUnauthorized, status, body)
		})
	}

	// Attribute-defs stay FLAT (token-contract layer): a remote-app self-token
	// may author its OWN defs but not another issuer's.
	status, body = remoteApplicationBoundaryRequestPath(t, server.URL, "/remote-applications/"+prefix+"-self-token/attribute-defs", http.MethodPost, remoteAppSelfToken, map[string]any{
		"key":        "tier-1",
		"definition": map[string]any{"rpm": 10},
	})
	require.Equal(t, http.StatusOK, status, body)
	var attrDef map[string]any
	require.NoError(t, json.Unmarshal([]byte(body), &attrDef))
	require.Equal(t, "tier-1", attrDef["key"])

	status, body = remoteApplicationBoundaryRequestPath(t, server.URL, "/remote-applications/"+prefix+"-app-a/attribute-defs", http.MethodPost, remoteAppSelfToken, map[string]any{
		"key":        "tier-1",
		"definition": map[string]any{"rpm": 10},
	})
	require.Equal(t, http.StatusForbidden, status, body)

	// managerA deletes app-a under orgA's path (slug-addressed) → 200, gone.
	status, body = remoteApplicationBoundaryDelete(t, server.URL, orgA.Slug, prefix+"-app-a", managerAToken)
	require.Equal(t, http.StatusOK, status, body)
	_, err = coreSvc.GetRemoteApplication(ctx, issuerA)
	require.ErrorIs(t, err, core.ErrRemoteApplicationNotFound)
}

func remoteApplicationBoundaryPG(t *testing.T) *pgxpool.Pool {
	t.Helper()
	dsn := os.Getenv("AUTHKIT_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("AUTHKIT_TEST_DATABASE_URL not set; skipping DB-backed test")
	}
	pool, err := pgxpool.New(context.Background(), dsn)
	require.NoError(t, err)
	t.Cleanup(pool.Close)
	return pool
}

func createBoundaryUser(t *testing.T, ctx context.Context, svc *core.Service, username string) *core.User {
	t.Helper()
	u, err := svc.CreateUser(ctx, username+"@example.com", username)
	require.NoError(t, err)
	return u
}

func issueBoundaryUserToken(t *testing.T, ctx context.Context, svc *core.Service, user *core.User) string {
	t.Helper()
	return issueBoundaryUserTokenWithExtra(t, ctx, svc, user, nil)
}

func issueBoundaryUserTokenWithSession(t *testing.T, ctx context.Context, svc *core.Service, user *core.User, sessionID string) string {
	t.Helper()
	return issueBoundaryUserTokenWithExtra(t, ctx, svc, user, map[string]any{"sid": sessionID})
}

func issueBoundaryUserTokenWithExtra(t *testing.T, ctx context.Context, svc *core.Service, user *core.User, extra map[string]any) string {
	t.Helper()
	email := ""
	if user.Email != nil {
		email = *user.Email
	}
	token, _, err := svc.IssueAccessToken(ctx, user.ID, email, extra)
	require.NoError(t, err)
	return token
}

func remoteApplicationBoundaryRegister(t *testing.T, baseURL, orgSlug, token string, body any) (int, string) {
	t.Helper()
	return remoteApplicationBoundaryRequestPath(t, baseURL, "/orgs/"+orgSlug+"/remote-applications", http.MethodPost, token, body)
}

func remoteApplicationBoundaryDelete(t *testing.T, baseURL, orgSlug, slug, token string) (int, string) {
	t.Helper()
	return remoteApplicationBoundaryRequestPath(t, baseURL, "/orgs/"+orgSlug+"/remote-applications/"+slug, http.MethodDelete, token, nil)
}

func remoteApplicationBoundaryRequestPath(t *testing.T, baseURL, path, method, token string, body any) (int, string) {
	t.Helper()
	payload, err := json.Marshal(body)
	require.NoError(t, err)
	req, err := http.NewRequest(method, baseURL+path, bytes.NewReader(payload))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	var buf bytes.Buffer
	_, _ = buf.ReadFrom(resp.Body)
	return resp.StatusCode, buf.String()
}

func mintBoundaryRemoteApplicationSelfToken(t *testing.T, ctx context.Context, svc *core.Service, verifier *Verifier, prefix string, org *core.Org) string {
	t.Helper()
	signer, err := jwtkit.NewRSASigner(2048, "boundary-remote-app")
	require.NoError(t, err)
	issuer := "https://" + prefix + "-self-token.example/issuer"
	_, err = svc.UpsertRemoteApplication(ctx, core.RemoteApplication{
		Slug:    prefix + "-self-token",
		OrgID:   org.ID,
		Issuer:  issuer,
		JWKSURI: "https://example.com/self-token-jwks.json",
		Enabled: true,
	})
	require.NoError(t, err)
	require.NoError(t, verifier.AddIssuer(issuer, []string{"authkit-boundary"}, IssuerOptions{
		RawKeys: map[string]crypto.PublicKey{signer.KID(): signer.PublicKey()},
		OrgSlug: org.Slug,
	}))
	token, err := core.MintRemoteApplicationAccessToken(ctx, signer, core.RemoteApplicationAccessParams{
		Issuer: issuer, Audiences: []string{"authkit-boundary"}, TTL: time.Minute,
	})
	require.NoError(t, err)
	return token
}

func mintBoundaryDelegatedToken(t *testing.T, verifier *Verifier, prefix string) string {
	t.Helper()
	signer, err := jwtkit.NewRSASigner(2048, "boundary-delegated")
	require.NoError(t, err)
	issuer := "https://" + prefix + "-delegated.example/issuer"
	require.NoError(t, verifier.AddIssuer(issuer, []string{"authkit-boundary"}, IssuerOptions{
		RawKeys: map[string]crypto.PublicKey{signer.KID(): signer.PublicKey()},
	}))
	token, err := MintDelegatedAccessToken(context.Background(), signer, DelegatedAccessParams{
		Issuer: issuer, Audiences: []string{"authkit-boundary"}, DelegatedSubject: "external-user", TTL: time.Minute,
	})
	require.NoError(t, err)
	return token
}
