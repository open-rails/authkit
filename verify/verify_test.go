package verify

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/errmodel"
	"github.com/open-rails/authkit/internal/ident"
	"github.com/open-rails/authkit/internal/jose"
	"github.com/open-rails/authkit/internal/testdpop"
	"github.com/open-rails/authkit/internal/testkeys"
	"github.com/open-rails/authkit/keys"
	"github.com/open-rails/helpers/auth"
	"github.com/stretchr/testify/require"
)

const (
	localIssuer = "https://auth.example"
	peerIssuer  = "https://peer.example"
	audience    = "resource"
)

// fixture is a Verifier trusting a local issuer (live key source) and a
// peer (static PEM keys), with the keys to sign as either.
type fixture struct {
	v           *Verifier
	local, peer keys.Signer
}

func newFixture(t *testing.T, opts ...VerifierOption) fixture {
	t.Helper()
	f := fixture{v: NewVerifier(opts...), local: testkeys.RSA("local"), peer: testkeys.EC("peer")}
	require.NoError(t, f.v.AddIssuer(localIssuer, []string{audience}, IssuerOptions{KeySource: testkeys.Source(f.local), IsLocal: true}))
	require.NoError(t, f.v.AddIssuer(peerIssuer, []string{audience}, IssuerOptions{Keys: []iam.RemoteApplicationKey{pemKey(t, f.peer)}}))
	return f
}

func pemKey(t *testing.T, s keys.Signer) iam.RemoteApplicationKey {
	der, err := x509.MarshalPKIXPublicKey(s.Public())
	require.NoError(t, err)
	return iam.RemoteApplicationKey{KID: s.KID(), PublicKeyPEM: string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))}
}

func sign(t *testing.T, s keys.Signer, typ, iss string, claims map[string]any) string {
	t.Helper()
	now := time.Now()
	base := map[string]any{"iss": iss, "aud": audience, "iat": now.Unix(), "exp": now.Add(time.Hour).Unix()}
	for k, v := range claims {
		if v == nil {
			delete(base, k)
		} else {
			base[k] = v
		}
	}
	token, err := jose.Sign(context.Background(), s, typ, base)
	require.NoError(t, err)
	return token
}

func codeOf(err error) errmodel.Code { return errmodel.CodeOf(err) }

// A local issuer's access token names a local user and carries no authority,
// whatever authority claims it holds; another issuer's names only a Subject.
func TestAccessTokens(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	cl, err := f.v.Verify(ctx, sign(t, f.local, jose.AccessTokenType, localIssuer, map[string]any{
		"sub": "user-1", "sid": "s-1", "permissions": []string{"root:*"}, "roles": []string{"owner"},
		"root_role": "root:admin", "amr": []string{"pwd", "mfa"}, "mfa_enrolled": true,
	}))
	require.NoError(t, err)
	require.Equal(t, iam.ActorUser, cl.Kind)
	require.Equal(t, jose.AccessTokenType, cl.JOSEType)
	require.Equal(t, "user-1", cl.UserID)
	require.Empty(t, cl.Subject)
	require.Empty(t, cl.Permissions, "native tokens carry no authority")
	require.False(t, cl.HasPermission(ident.Perm("root:users:ban")))
	require.Equal(t, "root:admin", cl.RootRole, "display only")
	require.True(t, cl.IsUser() && cl.MFAEnrolled && cl.HasAMR("mfa"))
	a, ok := ActorFromClaims(cl)
	require.True(t, ok)
	session, _ := a.Session()
	require.Equal(t, "s-1", session.SessionID, "the actor is bound to its session")

	cl, err = f.v.Verify(ctx, sign(t, f.peer, jose.AccessTokenType, peerIssuer, map[string]any{"sub": "ext-1"}))
	require.NoError(t, err)
	require.Equal(t, "ext-1", cl.Subject)
	require.Empty(t, cl.UserID, "another issuer never names a local user")
	require.False(t, cl.IsUser())
	_, ok = ActorFromClaims(cl)
	require.False(t, ok, "another issuer's user has no AuthKit authority")
	id, ok := cl.Identity()
	require.True(t, ok)
	require.Equal(t, auth.Identity{Kind: auth.KindUser, Issuer: peerIssuer, Subject: "ext-1"}, id)
}

// Each token class has one shape; anything else is refused with its code.
func TestTokenProfiles(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	for name, tc := range map[string]struct {
		typ    string
		claims map[string]any
		want   errmodel.Code
	}{
		"sub and delegated_sub":       {jose.AccessTokenType, map[string]any{"sub": "u", "delegated_sub": "d"}, errmodel.CodeConflictingSubject},
		"delegated with sub":          {jose.DelegatedAccessTokenType, map[string]any{"sub": "u"}, errmodel.CodeAccessTokenHasSub},
		"delegated_sub on access typ": {jose.AccessTokenType, map[string]any{"delegated_sub": "d"}, errmodel.CodeDelegatedAccessWrongTyp},
		"sub on another typ":          {"JWT", map[string]any{"sub": "u"}, errmodel.CodeAccessTokenWrongTyp},
		"no typ":                      {"", map[string]any{}, errmodel.CodeMissingTokenTyp},
		"remote-application typ":      {jose.RemoteApplicationAccessTokenType, map[string]any{}, errmodel.CodeUnsupportedTokenTyp},
		"delegated without subject":   {jose.DelegatedAccessTokenType, map[string]any{}, errmodel.CodeMissingDelegatedSub},
		"access without subject":      {jose.AccessTokenType, map[string]any{}, errmodel.CodeMissingSub},
		"expired":                     {jose.AccessTokenType, map[string]any{"sub": "u", "exp": time.Now().Add(-time.Hour).Unix()}, errmodel.CodeTokenExpired},
		"no exp":                      {jose.AccessTokenType, map[string]any{"sub": "u", "exp": nil}, errmodel.CodeMissingExp},
		"not yet valid":               {jose.AccessTokenType, map[string]any{"sub": "u", "nbf": time.Now().Add(time.Hour).Unix()}, errmodel.CodeTokenNotYetValid},
		"foreign audience":            {jose.AccessTokenType, map[string]any{"sub": "u", "aud": "elsewhere"}, errmodel.CodeBadAudience},
		"unknown issuer":              {jose.AccessTokenType, map[string]any{"sub": "u", "iss": "https://nobody.example"}, errmodel.CodeInvalidToken},
		"2FA-enrollment-only token":   {jose.AccessTokenType, map[string]any{"sub": "u", "2fa_enrollment": true}, errmodel.CodeForbidden},
		"cnf on an access token":      {jose.AccessTokenType, map[string]any{"sub": "u", "cnf": map[string]any{"jkt": jose.CertificateThumbprint([]byte("k"))}}, errmodel.CodeConfirmationWrongTokenType},
		"malformed cnf":               {jose.DelegatedAccessTokenType, map[string]any{"delegated_sub": "d", "cnf": map[string]any{"jkt": "short"}}, errmodel.CodeInvalidConfirmation},
		"two cnf members":             {jose.DelegatedAccessTokenType, map[string]any{"delegated_sub": "d", "cnf": map[string]any{"jkt": jose.CertificateThumbprint([]byte("a")), "x5t#S256": jose.CertificateThumbprint([]byte("b"))}}, errmodel.CodeInvalidConfirmation},
	} {
		_, err := f.v.Verify(ctx, sign(t, f.local, tc.typ, localIssuer, tc.claims))
		require.Equal(t, tc.want, codeOf(err), name)
	}
	// A token signed by another issuer's key never verifies as the local one.
	_, err := f.v.Verify(ctx, sign(t, f.peer, jose.AccessTokenType, localIssuer, map[string]any{"sub": "u"}))
	require.Equal(t, errmodel.CodeInvalidToken, codeOf(err))
}

// A delegated token names an external actor bounded by its permissions.
func TestDelegatedTokens(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	token := sign(t, f.peer, jose.DelegatedAccessTokenType, peerIssuer, map[string]any{
		"delegated_sub": "agent-7", "permissions": []string{"repo:read"}, "jti": "t-1", "attributes": map[string]any{"tier": "gold"},
	})
	cl, err := f.v.Verify(ctx, token)
	require.NoError(t, err)
	require.Equal(t, iam.ActorDelegated, cl.Kind)
	require.Equal(t, "agent-7", cl.DelegatedSubject)
	require.Equal(t, []string{"repo:read"}, cl.Permissions)
	require.JSONEq(t, `"gold"`, string(cl.Attributes["tier"]))
	require.Nil(t, cl.Group, "explicitly trusted delegation has no group binding")
	a, ok := ActorFromClaims(cl)
	require.True(t, ok)
	require.True(t, a.CeilingCovers(ident.Perm("repo:read")))
	require.False(t, a.CeilingCovers(ident.Perm("repo:write")))
}

// A certificate-bound token verifies only on a request whose TLS peer is its
// certificate; a DPoP-bound one only with a fresh proof of its key.
func TestSenderBoundDelegation(t *testing.T) {
	ctx := context.Background()
	replay := map[string]bool{}
	f := newFixture(t, WithDPoP(func(_ context.Context, key string, _ time.Duration) (bool, error) {
		if replay[key] {
			return false, nil
		}
		replay[key] = true
		return true, nil
	}), WithPublicURL("https://resource.example"))

	leaf, other := leafCertificate(t), leafCertificate(t)
	bound := sign(t, f.peer, jose.DelegatedAccessTokenType, peerIssuer, map[string]any{
		"delegated_sub": "d", "cnf": map[string]any{"x5t#S256": jose.CertificateThumbprint(leaf.Raw)},
	})
	_, err := f.v.Verify(ctx, bound)
	require.ErrorIs(t, err, ErrSenderProofRequired, "detached from its request")
	request := func(peer *x509.Certificate, scheme, token string) *http.Request {
		r := httptest.NewRequest(http.MethodGet, "https://resource.example/read", nil)
		r.Header.Set("Authorization", scheme+" "+token)
		if peer != nil {
			r.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{peer}}
		}
		return r
	}
	cl, err := f.v.VerifyRequest(request(leaf, "Bearer", bound))
	require.NoError(t, err)
	require.Equal(t, jose.CertificateThumbprint(leaf.Raw), cl.CertificateThumbprint)
	_, err = f.v.VerifyRequest(request(other, "Bearer", bound))
	require.ErrorIs(t, err, ErrSenderProofRequired, "another leaf")

	key := testdpop.Key(t)
	jkt := testdpop.Thumbprint(t, key)
	dpopBound := sign(t, f.peer, jose.DelegatedAccessTokenType, peerIssuer, map[string]any{"delegated_sub": "d", "cnf": map[string]any{"jkt": jkt}})
	r := request(nil, "DPoP", dpopBound)
	r.Header.Set("DPoP", testdpop.Proof(t, key, http.MethodGet, "https://resource.example/read", dpopBound, nil))
	cl, err = f.v.VerifyRequest(r)
	require.NoError(t, err)
	require.Equal(t, jkt, cl.JWKThumbprint)
	_, err = f.v.VerifyRequest(r)
	require.ErrorIs(t, err, ErrSenderProofRequired, "a proof is single-use")
	_, err = f.v.VerifyRequest(request(nil, "Bearer", dpopBound))
	require.ErrorIs(t, err, ErrSenderProofRequired, "no proof")
	unbound := sign(t, f.peer, jose.DelegatedAccessTokenType, peerIssuer, map[string]any{"delegated_sub": "d"})
	_, err = f.v.VerifyRequest(request(nil, "DPoP", unbound))
	require.ErrorIs(t, err, ErrSenderProofRequired, "a DPoP request needs a DPoP-bound token")
	_, err = NewVerifier().VerifyRequest(request(nil, "DPoP", dpopBound))
	require.Error(t, err, "no DPoP configured: nothing verifies")
}

func leafCertificate(t *testing.T) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: big.NewInt(now.UnixNano()), Subject: pkix.Name{CommonName: "delegate"},
		NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)
	leaf, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return leaf
}

// Registration takes exactly one key source and at least one audience, and
// a non-local registration never replaces the local issuer.
func TestAddIssuer(t *testing.T) {
	f := newFixture(t)
	s := testkeys.RSA("k")
	for name, opts := range map[string]IssuerOptions{
		"no key source":  {},
		"two sources":    {JWKSURI: "https://peer.example/jwks", KeySource: testkeys.Source(s)},
		"bad PEM":        {Keys: []iam.RemoteApplicationKey{{KID: "k", PublicKeyPEM: "nope"}}},
		"no kid":         {Keys: []iam.RemoteApplicationKey{{PublicKeyPEM: pemKey(t, s).PublicKeyPEM}}},
		"duplicate kid":  {Keys: []iam.RemoteApplicationKey{pemKey(t, s), pemKey(t, s)}},
		"over the local": {KeySource: testkeys.Source(s)},
	} {
		issuer := "https://new.example"
		if name == "over the local" {
			issuer = localIssuer
		}
		require.Error(t, f.v.AddIssuer(issuer, []string{audience}, opts), name)
	}
	require.Error(t, f.v.AddIssuer("https://new.example", []string{" "}, IssuerOptions{KeySource: testkeys.Source(s)}), "an issuer needs an audience")
	// The failed attempt left the local issuer as it was.
	_, err := f.v.Verify(context.Background(), sign(t, f.local, jose.AccessTokenType, localIssuer, map[string]any{"sub": "u"}))
	require.NoError(t, err)

	// A live key source is read on every verification: rotation needs no
	// re-registration.
	rotated := testkeys.RSA("rotated")
	source := testkeys.Source(f.local)
	require.NoError(t, f.v.AddIssuer(localIssuer, []string{audience}, IssuerOptions{KeySource: &source, IsLocal: true}))
	source = testkeys.Source(rotated)
	_, err = f.v.Verify(context.Background(), sign(t, rotated, jose.AccessTokenType, localIssuer, map[string]any{"sub": "u"}))
	require.NoError(t, err)
}

// The middleware answers AuthKit errors and panics on a route built wrong.
func TestMiddleware(t *testing.T) {
	f := newFixture(t)
	ok := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cl, _ := ClaimsFromContext(r.Context())
		_, _ = w.Write([]byte(cl.UserID))
	})
	call := func(h http.Handler, authorization string) (int, string) {
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		if authorization != "" {
			r.Header.Set("Authorization", authorization)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != http.StatusOK {
			var env iam.ErrorEnvelope
			require.NoError(t, json.Unmarshal(w.Body.Bytes(), &env))
			return w.Code, env.Error.Code
		}
		return w.Code, w.Body.String()
	}
	token := sign(t, f.local, jose.AccessTokenType, localIssuer, map[string]any{"sub": "user-1"})
	required, optional := Required(f.v)(ok), Optional(f.v)(ok)
	status, body := call(required, "Bearer "+token)
	require.Equal(t, http.StatusOK, status)
	require.Equal(t, "user-1", body)
	status, body = call(required, "")
	require.Equal(t, http.StatusUnauthorized, status)
	require.Equal(t, string(errmodel.CodeUnauthenticated), body)
	status, _ = call(optional, "")
	require.Equal(t, http.StatusOK, status, "anonymous passes Optional")
	status, body = call(optional, "Bearer garbage")
	require.Equal(t, http.StatusUnauthorized, status, "a present invalid credential is refused")
	require.Equal(t, string(errmodel.CodeInvalidToken), body)

	require.Panics(t, func() { Required(nil) })
	require.Panics(t, func() { RequireSession(nil) })
	require.Panics(t, func() { Sensitive(nil) })
	require.Panics(t, func() { RequirePermission(nil, ident.Perm("repo:read")) })
	require.Panics(t, func() { RequirePermissionOn(nil, iam.GroupRef{}, ident.Perm("repo:read")) })
}

// A Verifier's helpers/auth principal is identity only: it checks no
// permissions (the Client's does, live).
func TestPrincipalIsIdentityOnly(t *testing.T) {
	f := newFixture(t)
	var _ interface {
		AuthenticateRequest(context.Context, *http.Request) (auth.Principal, error)
	} = f.v
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("Authorization", "Bearer "+sign(t, f.local, jose.AccessTokenType, localIssuer, map[string]any{"sub": "user-1"}))
	p, err := f.v.AuthenticateRequest(r.Context(), r)
	require.NoError(t, err)
	require.Equal(t, auth.Identity{Kind: auth.KindUser, Issuer: localIssuer, Subject: "user-1"}, p.Identity())
	_, checks := p.(auth.PermissionChecker)
	require.False(t, checks)

	r.Header.Set("Authorization", "Bearer "+sign(t, f.local, jose.AccessTokenType, localIssuer, map[string]any{"sub": "user-1", "exp": time.Now().Add(-time.Hour).Unix()}))
	_, err = f.v.AuthenticateRequest(r.Context(), r)
	require.ErrorIs(t, err, auth.ErrExpired)
	require.ErrorIs(t, err, auth.ErrUnauthenticated)
	require.ErrorIs(t, err, iam.ErrTokenExpired)
}
