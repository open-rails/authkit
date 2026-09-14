package verify

import (
	"context"
	"crypto"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	authkit "github.com/open-rails/authkit"
	"github.com/open-rails/authkit/jwtkit"
	"github.com/stretchr/testify/require"
)

type authoritySource struct {
	app                  *authkit.RemoteApplication
	authority            authkit.RemoteApplicationAuthority
	getErr, authorityErr error
}

func (s *authoritySource) ListEnabledRemoteApplications(context.Context) ([]authkit.RemoteApplication, error) {
	if s.app == nil {
		return nil, nil
	}
	return []authkit.RemoteApplication{*s.app}, nil
}
func (s *authoritySource) GetRemoteApplication(context.Context, string) (*authkit.RemoteApplication, error) {
	return s.app, s.getErr
}
func (s *authoritySource) ResolveRemoteApplicationAuthority(context.Context, string) (authkit.RemoteApplicationAuthority, error) {
	return s.authority, s.authorityErr
}
func (s *authoritySource) ResolveAPIKeyDetailed(context.Context, string, string) (authkit.ResolvedAPIKey, error) {
	return authkit.ResolvedAPIKey{}, errors.New("unused")
}

func storedVerifier(t *testing.T) (*Verifier, *authoritySource, *jwtkit.RSASigner) {
	t.Helper()
	app, signer := staticApp(t, "app", "https://application.example")
	app.ID = "application-id"
	src := &authoritySource{app: &app, authority: authkit.RemoteApplicationAuthority{
		Permissions: []string{"repo:read"}, PermissionGroupID: "group-alpha", AuthorityIssuer: "https://local.example", Persona: "repo", InstanceSlug: "alpha",
	}}
	v := NewVerifier().WithService(src)
	require.NoError(t, v.LoadRemoteApplications(context.Background(), src, []string{"resource"}))
	return v, src, signer
}

func TestStoredIssuerRevocationAcrossVerificationEntrypoints(t *testing.T) {
	ctx := context.Background()
	for _, state := range []string{"disabled", "deleted", "lookup error"} {
		t.Run(state, func(t *testing.T) {
			v, src, signer := storedVerifier(t)
			leaf := confirmationLeaf(t)
			sum := sha256.Sum256(leaf.Raw)
			for _, bound := range []bool{false, true} {
				for _, permissions := range [][]string{nil, {"repo:read"}, {"root:*"}} {
					mc := map[string]any{"iss": src.app.Issuer, "aud": "resource", "delegated_sub": "external-user", "exp": time.Now().Add(time.Minute).Unix()}
					if permissions != nil {
						mc["permissions"] = permissions
					}
					if bound {
						mc["cnf"] = map[string]any{"x5t#S256": base64.RawURLEncoding.EncodeToString(sum[:])}
					}
					token, err := signer.SignWithHeaders(ctx, mc, map[string]any{"typ": DelegatedAccessTokenType})
					require.NoError(t, err)
					req := httptest.NewRequest(http.MethodGet, "https://resource.example/read", nil)
					req.Header.Set("Authorization", "Bearer "+token)
					if bound {
						req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{leaf}}
					}
					serviceToken, err := signer.SignWithHeaders(ctx, map[string]any{
						"iss": src.app.Issuer, "aud": "resource", "sub": "service-actor", "token_use": authkit.ServiceJWTTokenUse,
						"iat": time.Now().Unix(), "nbf": time.Now().Unix(), "exp": time.Now().Add(time.Minute).Unix(), "jti": "service-token",
					}, map[string]any{"typ": "service+jwt"})
					require.NoError(t, err)
					_, err = v.VerifyServiceJWT(ctx, serviceToken)
					require.NoError(t, err)
					app := *src.app
					_, _, err = v.VerifyDelegatedAccessRequest(req)
					if len(permissions) > 0 && permissions[0] == "root:*" {
						require.Error(t, err)
					} else {
						require.NoError(t, err)
					}
					switch state {
					case "disabled":
						src.app.Enabled = false
					case "deleted":
						src.app = nil
					case "lookup error":
						src.getErr = errors.New("store unavailable")
					}
					_, err = v.VerifyServiceJWT(ctx, serviceToken)
					require.Error(t, err)
					_, err = v.VerifyClaims(ctx, token)
					require.Error(t, err)
					_, err = v.Verify(ctx, token)
					require.Error(t, err)
					_, _, err = v.VerifyDelegatedAccess(ctx, token)
					require.Error(t, err)
					_, _, err = v.VerifyDelegatedAccessRequest(req)
					require.Error(t, err)
					_, err = v.VerifyRequest(req)
					require.Error(t, err)
					require.Error(t, v.ValidateDocumentIssuer(ctx, app.Issuer))
					doc := testSignedDocument(t, signer, app.Issuer)
					_, err = v.VerifyDocument(ctx, doc, verifyOptions(app.Issuer, doc))
					require.Error(t, err)
					src.app = &app
					src.getErr = nil
				}
			}
		})
	}
}

func TestDelegatedStoredAuthorityAndScopeFailClosed(t *testing.T) {
	ctx := context.Background()
	v, src, signer := storedVerifier(t)
	token, err := signer.SignWithHeaders(ctx, map[string]any{
		"iss": src.app.Issuer, "aud": "resource", "delegated_sub": "actor", "permissions": []string{"repo:read"}, "exp": time.Now().Add(time.Minute).Unix(),
	}, map[string]any{"typ": DelegatedAccessTokenType})
	require.NoError(t, err)
	cl, principal, err := v.VerifyDelegatedAccess(ctx, token)
	require.NoError(t, err)
	require.NotNil(t, principal.PermissionGroup)
	require.Equal(t, &PermissionScope{GroupID: cl.PermissionGroupID, AuthorityIssuer: cl.PermissionGroupAuthorityIssuer, Persona: authkit.Persona(cl.PermissionGroupPersona), Instance: cl.PermissionGroupInstance}, principal.PermissionGroup)
	for name, scope := range map[string]PermissionScope{
		"own":              {GroupID: "group-alpha", AuthorityIssuer: "https://local.example", Persona: "repo"},
		"different UUID":   {GroupID: "group-beta", AuthorityIssuer: "https://local.example", Persona: "repo"},
		"different issuer": {GroupID: "group-alpha", AuthorityIssuer: "https://other.example", Persona: "repo"},
		"absent":           {},
	} {
		allowed, err := Allow(ctx, nil, cl, "repo:read", scope)
		require.NoError(t, err)
		require.Equal(t, name == "own", allowed, name)
	}
	src.authority = authkit.RemoteApplicationAuthority{Permissions: []string{"repo:read"}}
	cl, err = v.Verify(ctx, token)
	require.NoError(t, err)
	require.True(t, cl.BoundToPermissionGroup(), "missing binding must not become platform-wide delegation")
	allowed, err := Allow(ctx, nil, cl, "repo:read", PermissionScope{})
	require.NoError(t, err)
	require.False(t, allowed)
	src.authorityErr = errors.New("authority unavailable")
	_, err = v.Verify(ctx, token)
	require.Error(t, err)
}

func TestExternalIdentityNeverBecomesLocalUser(t *testing.T) {
	ctx := context.Background()
	signer, err := jwtkit.NewRSASigner(2048, "identity")
	require.NoError(t, err)
	v := NewVerifier()
	for _, issuer := range []string{"https://identity-a.example", "https://identity-b.example"} {
		require.NoError(t, v.AddIssuer(issuer, []string{"resource"}, IssuerOptions{RawKeys: map[string]crypto.PublicKey{signer.KID(): signer.PublicKey()}}))
		cl, err := v.Verify(ctx, mintStatelessAccess(t, signer, issuer, "resource", "same-user-id"))
		require.NoError(t, err)
		require.Empty(t, cl.UserID)
		require.False(t, cl.IsUser())
		require.Equal(t, authkit.Principal{Kind: authkit.PrincipalKindUser, Issuer: issuer, Subject: "same-user-id"}, cl.Principal())
		allowed, err := Allow(ctx, nil, cl, "repo:read", PermissionScope{GroupID: "local-group"})
		require.NoError(t, err)
		require.False(t, allowed)
	}
}

func TestPermissionCatalogRunsOnEveryTypedDelegation(t *testing.T) {
	ctx := context.Background()
	v, signer := confirmationVerifier(t)
	v.permValidator = func([]string) error { return errors.New("unknown catalog permission") }
	token := signTyped(t, signer, DelegatedAccessTokenType, delegatedClaims(map[string]any{"permissions": []string{"unknown"}}))
	_, err := v.Verify(ctx, token)
	require.Error(t, err)
	_, _, err = v.VerifyDelegatedAccess(ctx, token)
	require.Error(t, err)
	req := httptest.NewRequest(http.MethodGet, "https://resource.example/read", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	_, err = v.VerifyRequest(req)
	require.Error(t, err)
	_, _, err = v.VerifyDelegatedAccessRequest(req)
	require.Error(t, err)
}

func TestStoredApplicationTrustModeChangesReplaceKeys(t *testing.T) {
	ctx := context.Background()
	v, src, first := storedVerifier(t)
	second, err := jwtkit.NewRSASigner(2048, first.KID())
	require.NoError(t, err)
	jwks := jwtkit.JWKS{Keys: []jwtkit.JWK{jwtkit.PublicToJWK(second.PublicKey(), second.KID(), second.Algorithm())}}
	endpoint := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { jwtkit.ServeJWKS(w, r, jwks) }))
	defer endpoint.Close()
	mint := func(signer *jwtkit.RSASigner) string {
		token, err := signer.SignWithHeaders(ctx, map[string]any{"iss": src.app.Issuer, "aud": "resource", "exp": time.Now().Add(time.Minute).Unix()}, map[string]any{"typ": RemoteApplicationAccessTokenType})
		require.NoError(t, err)
		return token
	}
	old, fresh := mint(first), mint(second)
	_, err = v.Verify(ctx, old)
	require.NoError(t, err)
	src.app.Mode = authkit.RemoteAppModeJWKS
	src.app.JWKSURI = endpoint.URL
	_, err = v.Verify(ctx, fresh)
	require.NoError(t, err)
	_, err = v.Verify(ctx, old)
	require.Error(t, err)
	src.app.Mode = authkit.RemoteAppModeStatic
	src.app.JWKSURI = ""
	_, err = v.Verify(ctx, old)
	require.NoError(t, err)
	_, err = v.Verify(ctx, fresh)
	require.Error(t, err, "JWKS cache must not override live static keys")
	jwks = jwtkit.JWKS{Keys: []jwtkit.JWK{jwtkit.PublicToJWK(first.PublicKey(), first.KID(), first.Algorithm())}}
	src.app.Mode = authkit.RemoteAppModeJWKS
	src.app.JWKSURI = endpoint.URL
	_, err = v.Verify(ctx, old)
	require.NoError(t, err, "re-enabled JWKS must fetch its current keys")
	_, err = v.Verify(ctx, fresh)
	require.Error(t, err)
}

func TestStoredDelegationCannotOmitAuthorityBackend(t *testing.T) {
	ctx := context.Background()
	_, src, signer := storedVerifier(t)
	v := NewVerifier()
	require.NoError(t, v.LoadRemoteApplications(ctx, src, []string{"resource"}))
	token, err := signer.SignWithHeaders(ctx, map[string]any{"iss": src.app.Issuer, "aud": "resource", "delegated_sub": "actor", "exp": time.Now().Add(time.Minute).Unix()}, map[string]any{"typ": DelegatedAccessTokenType})
	require.NoError(t, err)
	_, _, err = v.VerifyDelegatedAccess(ctx, token)
	require.Error(t, err, "even empty stored delegation requires live authority resolution")
	stateless := NewVerifier()
	require.NoError(t, stateless.AddIssuer(src.app.Issuer, []string{"resource"}, IssuerOptions{RawKeys: map[string]crypto.PublicKey{signer.KID(): signer.PublicKey()}}))
	_, principal, err := stateless.VerifyDelegatedAccess(ctx, token)
	require.NoError(t, err)
	require.Nil(t, principal.PermissionGroup, "explicit platform trust remains unbound")
}

func TestApplicationRegistrationCannotReplaceExplicitIssuerTrust(t *testing.T) {
	ctx := context.Background()
	_, src, applicationSigner := storedVerifier(t)
	platformSigner, err := jwtkit.NewRSASigner(2048, applicationSigner.KID())
	require.NoError(t, err)
	v := NewVerifier().WithService(src)
	require.NoError(t, v.AddIssuer(src.app.Issuer, []string{"resource"}, IssuerOptions{RawKeys: map[string]crypto.PublicKey{platformSigner.KID(): platformSigner.PublicKey()}}))
	require.Error(t, v.LoadRemoteApplications(ctx, src, []string{"resource"}), "application registrations cannot change an explicitly trusted platform key")
	_, err = v.Verify(ctx, mintStatelessAccess(t, platformSigner, src.app.Issuer, "resource", "external-user"))
	require.NoError(t, err)
	_, err = v.Verify(ctx, mintStatelessAccess(t, applicationSigner, src.app.Issuer, "resource", "external-user"))
	require.Error(t, err)
}
