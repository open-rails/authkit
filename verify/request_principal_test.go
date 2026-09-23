package verify

import (
	"context"
	"crypto"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	jwt "github.com/golang-jwt/jwt/v5"
	authkit "github.com/open-rails/authkit"
	"github.com/open-rails/authkit/internal/testdpop"
	"github.com/open-rails/helpers/auth"
	"github.com/stretchr/testify/require"
)

// Exact return types satisfy an independently declared consumer contract.
var _ interface {
	AuthenticateRequest(context.Context, *http.Request) (auth.Principal, error)
} = (*Verifier)(nil)

type principalAuthority struct {
	allowed bool
	calls   int
	err     error
}

func (s *principalAuthority) CanOnGroup(_ context.Context, subject authkit.Subject, group string, permission authkit.Perm) (bool, error) {
	s.calls++
	return s.allowed && subject == authkit.UserSubject("native-user") && group == "group-1" && permission == "repo:read", s.err
}

type principalLiveness struct{ calls int }

func (s *principalLiveness) UserLivenessByIDs(context.Context, []string) (map[string]authkit.UserLiveness, error) {
	s.calls++
	return map[string]authkit.UserLiveness{"native-user": {Allowed: false}}, nil
}

func principalRequest(token string) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "https://resource.example/read", nil)
	r.Header.Set("Authorization", "Bearer "+token)
	return r
}

func TestRequestPrincipalNativeAuthorityAndExplicitLiveness(t *testing.T) {
	v, signer := confirmationVerifier(t)
	require.NoError(t, v.AddIssuer(confirmationIssuer, []string{"resource"}, IssuerOptions{IsLocal: true, RawKeys: map[string]crypto.PublicKey{signer.KID(): signer.PublicKey()}}))
	authority, live := &principalAuthority{allowed: true}, &principalLiveness{}
	v.WithPermissionChecker(authority, confirmationIssuer).WithLiveness(live)
	token := mintStatelessAccess(t, signer, confirmationIssuer, "resource", "native-user")
	r := principalRequest(token)
	p, err := v.AuthenticateRequest(r.Context(), r)
	require.NoError(t, err)
	require.Equal(t, auth.Identity{Kind: auth.KindUser, Issuer: confirmationIssuer, Subject: "native-user"}, p.Identity())
	require.Zero(t, live.calls, "ordinary JWT auth must not apply the configured ban gate")
	checker := p.(auth.PermissionChecker)
	scope := auth.Scope{Authority: confirmationIssuer, ID: "group-1"}
	allowed, err := checker.Can(r.Context(), scope, "repo:read")
	require.NoError(t, err)
	require.True(t, allowed)
	authority.allowed = false
	allowed, err = checker.Can(r.Context(), scope, "repo:read")
	require.NoError(t, err)
	require.False(t, allowed, "permission removal must affect an already authenticated principal")
	require.Equal(t, 2, authority.calls)
	allowed, err = checker.Can(r.Context(), auth.Scope{Authority: "https://other.example", ID: "group-1"}, "repo:read")
	require.NoError(t, err)
	require.False(t, allowed)
	require.Equal(t, 2, authority.calls)
	_, err = v.AuthenticateRequestLive(r.Context(), r)
	require.ErrorIs(t, err, auth.ErrUnauthenticated)
	require.Equal(t, 1, live.calls)

	// Context values cannot substitute for verification by this verifier.
	bad := principalRequest("invalid")
	_, err = v.AuthenticateRequest(SetClaims(bad.Context(), Claims{UserID: "native-user", Issuer: confirmationIssuer}), bad)
	require.ErrorIs(t, err, auth.ErrUnauthenticated)
	for name, tok := range map[string]string{
		"wrong audience": mintStatelessAccess(t, signer, confirmationIssuer, "another-resource", "native-user"),
		"wrong issuer":   mintStatelessAccess(t, signer, "https://other.example", "resource", "native-user"),
	} {
		t.Run(name, func(t *testing.T) {
			r := principalRequest(tok)
			_, err := v.AuthenticateRequest(r.Context(), r)
			require.ErrorIs(t, err, auth.ErrUnauthenticated)
		})
	}
}

type principalAPIKeySource struct {
	authoritySource
	resolved authkit.ResolvedAPIKey
	err      error
	calls    int
}

func (s *principalAPIKeySource) ResolveAPIKeyDetailed(_ context.Context, key, secret string) (authkit.ResolvedAPIKey, error) {
	s.calls++
	if key != "presented" || secret != "secret" {
		return authkit.ResolvedAPIKey{}, authkit.ErrInvalidAccessToken
	}
	return s.resolved, s.err
}

func TestRequestPrincipalAPIKeyIdentityAndScopeCeiling(t *testing.T) {
	source := &principalAPIKeySource{resolved: authkit.ResolvedAPIKey{APIKeyID: "immutable-key-id", PermissionGroupID: "group-1", AuthorityIssuer: confirmationIssuer, Persona: "repo", Permissions: []string{"repo:read"}}}
	v := NewVerifier().WithService(source).WithPermissionChecker(source, confirmationIssuer)
	r := principalRequest(authkit.FormatAPIKey("", "presented", "secret"))
	p, err := v.AuthenticateRequest(r.Context(), r)
	require.NoError(t, err)
	require.Equal(t, auth.Identity{Kind: auth.KindAPIKey, Issuer: confirmationIssuer, Subject: "immutable-key-id"}, p.Identity())
	checker := p.(auth.PermissionChecker)
	for _, tc := range []struct {
		scope      auth.Scope
		permission string
		allowed    bool
	}{
		{auth.Scope{Authority: confirmationIssuer, ID: "group-1"}, "repo:read", true},
		{auth.Scope{Authority: confirmationIssuer, ID: "group-2"}, "repo:read", false},
		{auth.Scope{Authority: "https://other.example", ID: "group-1"}, "repo:read", false},
		{auth.Scope{Authority: confirmationIssuer, ID: "group-1"}, "repo:write", false},
		{auth.Scope{}, "repo:read", false},
	} {
		allowed, err := checker.Can(r.Context(), tc.scope, tc.permission)
		require.NoError(t, err)
		require.Equal(t, tc.allowed, allowed)
	}
	require.Equal(t, 1, source.calls, "permission checks must not resolve or verify the key again")
	source.resolved.Permissions[0] = "repo:*"
	allowed, err := checker.Can(r.Context(), auth.Scope{Authority: confirmationIssuer, ID: "group-1"}, "repo:write")
	require.NoError(t, err)
	require.False(t, allowed, "backend-owned slices cannot enlarge a captured credential ceiling")
	deleted := time.Now()
	source.deletedAt = &deleted
	allowed, err = checker.Can(r.Context(), auth.Scope{Authority: confirmationIssuer, ID: "group-1"}, "repo:read")
	require.NoError(t, err)
	require.False(t, allowed, "same captured credential observes group retirement")
	require.Equal(t, 1, source.calls, "group liveness never repeats credential verification")
	for _, failure := range []struct{ source, neutral error }{{authkit.ErrAccessTokenExpired, auth.ErrExpired}, {authkit.ErrAccessTokenRevoked, auth.ErrRevoked}} {
		source.err = failure.source
		_, err := v.AuthenticateRequest(r.Context(), r)
		require.ErrorIs(t, err, failure.neutral)
		require.ErrorIs(t, err, auth.ErrUnauthenticated)
	}
}

func TestRequestPrincipalDPoPVerifiedOnceAndScoped(t *testing.T) {
	v, source, signer := storedVerifier(t)
	key := testdpop.Key(t)
	public, err := key.PublicKey.Bytes()
	require.NoError(t, err)
	thumbprint := sha256.Sum256(fmt.Appendf(nil, `{"crv":"P-256","kty":"EC","x":"%s","y":"%s"}`, base64.RawURLEncoding.EncodeToString(public[1:33]), base64.RawURLEncoding.EncodeToString(public[33:])))
	claims := jwt.MapClaims{"iss": source.app.Issuer, "aud": "resource", "delegated_sub": "external-user", "permissions": []string{"repo:read"}, "exp": time.Now().Add(time.Minute).Unix(), "cnf": map[string]any{"jkt": base64.RawURLEncoding.EncodeToString(thumbprint[:])}}
	token := signTyped(t, signer, DelegatedAccessTokenType, claims)
	proofCalls := 0
	seen := map[string]bool{}
	WithDPoP(func(_ context.Context, key string, _ time.Duration) (bool, error) {
		proofCalls++
		if seen[key] {
			return false, nil
		}
		seen[key] = true
		return true, nil
	}, func(r *http.Request) string { return "https://resource.example" + r.URL.Path })(v)
	r := principalRequest(token)
	r.Header.Set("Authorization", "DPoP "+token)
	r.Header.Set("DPoP", testdpop.Proof(t, key, r.Method, r.URL.String(), token, nil))
	p, err := v.AuthenticateRequest(r.Context(), r)
	require.NoError(t, err)
	require.Equal(t, auth.KindDelegated, p.Identity().Kind)
	require.Equal(t, "external-user", p.Identity().Subject)
	for range 2 {
		allowed, err := p.(auth.PermissionChecker).Can(r.Context(), auth.Scope{Authority: "https://local.example", ID: "group-alpha"}, "repo:read")
		require.NoError(t, err)
		require.True(t, allowed)
	}
	require.Equal(t, 1, proofCalls)
	_, err = v.AuthenticateRequest(r.Context(), r)
	require.ErrorIs(t, err, auth.ErrSenderProofRequired)
	require.Equal(t, 2, proofCalls, "another authentication is a replay, not a cache hit")

	// A host that already ran trusted middleware opts into the explicit handoff
	// after its own admission policy. The factory never reads arbitrary context.
	r.Header.Set("DPoP", testdpop.Proof(t, key, r.Method, r.URL.String(), token, nil))
	handler := Required(v)(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		cl, ok := ClaimsFromContext(request.Context())
		require.True(t, ok)
		principal, err := v.PrincipalFromVerifiedClaims(cl)
		require.NoError(t, err)
		for range 2 {
			allowed, err := principal.(auth.PermissionChecker).Can(request.Context(), auth.Scope{Authority: "https://local.example", ID: "group-alpha"}, "repo:read")
			require.NoError(t, err)
			require.True(t, allowed)
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, r)
	require.Equal(t, http.StatusNoContent, recorder.Code)
	require.Equal(t, 3, proofCalls)
	recorder = httptest.NewRecorder()
	handler.ServeHTTP(recorder, r.Clone(r.Context()))
	require.Equal(t, http.StatusUnauthorized, recorder.Code)
	require.Equal(t, 4, proofCalls)
}

func TestRequestPrincipalRemoteApplicationUsesImmutableIdentity(t *testing.T) {
	v, source, signer := storedVerifier(t)
	token := signTyped(t, signer, RemoteApplicationAccessTokenType, jwt.MapClaims{"iss": source.app.Issuer, "aud": "resource", "exp": time.Now().Add(time.Minute).Unix()})
	r := principalRequest(token)
	p, err := v.AuthenticateRequest(r.Context(), r)
	require.NoError(t, err)
	require.Equal(t, auth.KindRemoteApplication, p.Identity().Kind)
	require.Equal(t, source.app.ID, p.Identity().Subject)
	source.app.Slug = "renamed-application"
	require.Equal(t, source.app.ID, p.Identity().Subject)
}

func TestRequestPrincipalCannotUpgradeCredentialProvenance(t *testing.T) {
	for _, tc := range []struct {
		name   string
		local  bool
		typ    string
		kind   auth.Kind
		claims jwt.MapClaims
	}{
		{"external user", false, AccessTokenType, auth.KindUser, jwt.MapClaims{"sub": "native-user"}},
		{"device key", true, AccessTokenType, auth.KindDeviceKey, jwt.MapClaims{"sub": "native-user", "device_key_id": "device-1"}},
		{"unbound delegation", false, DelegatedAccessTokenType, auth.KindDelegated, jwt.MapClaims{"delegated_sub": "native-user", "permissions": []string{"repo:*"}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			v, signer := confirmationVerifier(t)
			require.NoError(t, v.AddIssuer(confirmationIssuer, []string{"resource"}, IssuerOptions{IsLocal: tc.local, RawKeys: map[string]crypto.PublicKey{signer.KID(): signer.PublicKey()}}))
			authority := &principalAuthority{allowed: true}
			v.WithPermissionChecker(authority, confirmationIssuer)
			tc.claims["iss"], tc.claims["aud"], tc.claims["exp"] = confirmationIssuer, "resource", time.Now().Add(time.Minute).Unix()
			r := principalRequest(signTyped(t, signer, tc.typ, tc.claims))
			principal, err := v.AuthenticateRequest(r.Context(), r)
			require.NoError(t, err)
			require.Equal(t, tc.kind, principal.Identity().Kind)
			allowed, err := principal.(auth.PermissionChecker).Can(r.Context(), auth.Scope{Authority: confirmationIssuer, ID: "group-1"}, "repo:read")
			require.NoError(t, err)
			require.False(t, allowed)
			require.Zero(t, authority.calls, "non-native credentials must never look up a native user's authority")
		})
	}
}

func TestScopedMachinePermissionRequiresLiveGroupReader(t *testing.T) {
	cl := Claims{PermissionGroupID: "group", PermissionGroupAuthorityIssuer: "https://issuer.test", PermissionGroupPersona: "repo", Permissions: []string{"repo:read"}, APIKeyID: "key"}
	scope := PermissionScope{GroupID: "group", AuthorityIssuer: "https://issuer.test", Persona: "repo"}
	allowed, err := Allow(t.Context(), nil, cl, "repo:read", scope)
	require.ErrorIs(t, err, auth.ErrUnavailable)
	require.False(t, allowed)
	allowed, err = Allow(t.Context(), &principalAuthority{allowed: true}, cl, "repo:read", scope)
	require.ErrorIs(t, err, auth.ErrUnavailable)
	require.False(t, allowed)
}
