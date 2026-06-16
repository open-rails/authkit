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
		ServiceTokenPrefix:       "authkit",
	}, core.Keyset{
		Active:     signer,
		PublicKeys: map[string]crypto.PublicKey{signer.KID(): signer.PublicKey()},
	}).WithPostgres(pool)
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
	require.NoError(t, coreSvc.SetRolePermissions(ctx, orgA.Slug, "remote-app-manager", []string{core.PermOrgRemoteAppsManage}))
	require.NoError(t, coreSvc.AddMember(ctx, orgA.Slug, managerA.ID))
	require.NoError(t, coreSvc.AssignRole(ctx, orgA.Slug, managerA.ID, "remote-app-manager"))
	require.NoError(t, coreSvc.AddMember(ctx, orgA.Slug, viewerA.ID))

	require.NoError(t, coreSvc.DefineRole(ctx, orgB.Slug, "remote-app-manager"))
	require.NoError(t, coreSvc.SetRolePermissions(ctx, orgB.Slug, "remote-app-manager", []string{core.PermOrgRemoteAppsManage}))
	require.NoError(t, coreSvc.AddMember(ctx, orgB.Slug, managerB.ID))
	require.NoError(t, coreSvc.AssignRole(ctx, orgB.Slug, managerB.ID, "remote-app-manager"))

	managerAToken := issueBoundaryUserToken(t, ctx, coreSvc, managerA)
	viewerAToken := issueBoundaryUserToken(t, ctx, coreSvc, viewerA)
	managerBToken := issueBoundaryUserToken(t, ctx, coreSvc, managerB)

	issuerA := "https://" + prefix + "-app-a.example/issuer"
	status, body := remoteApplicationBoundaryRequest(t, server.URL, http.MethodPost, "", map[string]any{
		"slug": "missing-auth", "issuer": issuerA, "org_id": orgA.ID, "jwks_uri": "https://example.com/jwks.json",
	})
	require.Equal(t, http.StatusUnauthorized, status, body)

	status, body = remoteApplicationBoundaryRequest(t, server.URL, http.MethodPost, managerAToken, map[string]any{
		"slug": prefix + "-bad", "org_id": orgA.ID, "jwks_uri": "https://example.com/jwks.json",
	})
	require.Equal(t, http.StatusBadRequest, status, body)

	status, body = remoteApplicationBoundaryRequest(t, server.URL, http.MethodPost, managerAToken, map[string]any{
		"slug": prefix + "-app-a", "issuer": issuerA, "org_id": orgA.ID, "jwks_uri": "https://example.com/jwks.json",
	})
	require.Equal(t, http.StatusOK, status, body)
	registered, err := coreSvc.GetRemoteApplication(ctx, issuerA)
	require.NoError(t, err)
	require.Equal(t, orgA.ID, registered.OrgID)

	status, body = remoteApplicationBoundaryRequest(t, server.URL, http.MethodPost, viewerAToken, map[string]any{
		"slug": prefix + "-viewer", "issuer": "https://" + prefix + "-viewer.example/issuer", "org_id": orgA.ID, "jwks_uri": "https://example.com/viewer-jwks.json",
	})
	require.Equal(t, http.StatusForbidden, status, body)

	status, body = remoteApplicationBoundaryRequest(t, server.URL, http.MethodPost, managerBToken, map[string]any{
		"slug": prefix + "-app-a", "issuer": issuerA, "org_id": orgB.ID, "jwks_uri": "https://example.com/cross-jwks.json",
	})
	require.Equal(t, http.StatusForbidden, status, body)

	status, body = remoteApplicationBoundaryRequest(t, server.URL, http.MethodPost, managerAToken, map[string]any{
		"slug": prefix + "-unowned-new", "issuer": "https://" + prefix + "-unowned-new.example/issuer", "jwks_uri": "https://example.com/unowned-jwks.json",
	})
	require.Equal(t, http.StatusForbidden, status, body)

	_, err = coreSvc.UpsertRemoteApplication(ctx, core.RemoteApplication{
		Slug:    prefix + "-bootstrap",
		Issuer:  "https://" + prefix + "-bootstrap.example/issuer",
		JWKSURI: "https://example.com/bootstrap-jwks.json",
		Enabled: true,
	})
	require.NoError(t, err)
	status, body = remoteApplicationBoundaryRequest(t, server.URL, http.MethodDelete, managerAToken, map[string]any{
		"issuer": "https://" + prefix + "-bootstrap.example/issuer",
	})
	require.Equal(t, http.StatusForbidden, status, body)

	_, servicePlaintext, err := coreSvc.MintServiceTokenWithOptions(ctx, orgA.Slug, core.ServiceTokenMintOptions{
		Name:        prefix + "-service-token",
		Permissions: []string{core.PermOrgRemoteAppsManage},
		CreatedBy:   ownerA.ID,
	})
	require.NoError(t, err)
	remoteAppSelfToken := mintBoundaryRemoteApplicationSelfToken(t, ctx, coreSvc, verifier, prefix, orgA)
	delegatedToken := mintBoundaryDelegatedToken(t, verifier, prefix)
	for name, token := range map[string]string{
		"service-token":           servicePlaintext,
		"remote-application-self": remoteAppSelfToken,
		"delegated-token":         delegatedToken,
	} {
		t.Run("rejects "+name, func(t *testing.T) {
			status, body := remoteApplicationBoundaryRequest(t, server.URL, http.MethodPost, token, map[string]any{
				"slug": prefix + "-" + name, "issuer": "https://" + prefix + "-" + name + ".example/issuer", "org_id": orgA.ID, "jwks_uri": "https://example.com/credential-jwks.json",
			})
			require.Equal(t, http.StatusUnauthorized, status, body)
		})
	}

	status, body = remoteApplicationBoundaryRequest(t, server.URL, http.MethodDelete, managerAToken, map[string]any{"issuer": issuerA})
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
	email := ""
	if user.Email != nil {
		email = *user.Email
	}
	token, _, err := svc.IssueAccessToken(ctx, user.ID, email, nil)
	require.NoError(t, err)
	return token
}

func remoteApplicationBoundaryRequest(t *testing.T, baseURL, method, token string, body any) (int, string) {
	t.Helper()
	payload, err := json.Marshal(body)
	require.NoError(t, err)
	req, err := http.NewRequest(method, baseURL+"/remote-applications", bytes.NewReader(payload))
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
