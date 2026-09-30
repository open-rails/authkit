package apitest_test

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	jwt "github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/open-rails/authkit"
	"github.com/open-rails/authkit/authtest"
	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/testdpop"
	"github.com/open-rails/authkit/jwtkit"
	"github.com/open-rails/authkit/verify"
)

// The delegated mint's bounds, hardcoded from unexported sources: the TTL
// clamps (engine delegated_config.go) and the size limits (httpapi
// delegated_token.go).
const (
	delegatedTTLFloor         = time.Minute
	delegatedTTLDefault       = 15 * time.Minute
	delegatedTTLCeiling       = time.Hour
	maxDelegateCertificateDER = 8 << 10
	maxRequestedGrantBytes    = 16 << 10
	maxDelegatedTokenBytes    = 16 << 10
)

// Real HTTP issuer -> resource requests prove that delegated authority still
// comes only from the host grant, with browser key possession enforced on
// issuance and every protected request.
func TestBrowserDelegationWorkflow(t *testing.T) {
	ctx := t.Context()
	keys := newSwappableKeySource(t, "dpop-kid")
	var authorizations atomic.Int32
	var observed iam.DelegationRequest
	var mu sync.Mutex
	authorizer := func(_ context.Context, req iam.DelegationRequest) (iam.DelegationGrant, error) {
		authorizations.Add(1)
		mu.Lock()
		observed = req
		mu.Unlock()
		if string(req.RequestedGrant) == `{"refuse":true}` {
			return iam.DelegationGrant{}, iam.ErrDelegationRefused
		}
		return iam.DelegationGrant{Permissions: []string{"resource:read"}, Attributes: map[string]any{"tenant": "cozy"}}, nil
	}
	auth, _ := authtest.New(t, authtest.WithConfig(func(c *authkit.Config) {
		c.Keys.Source = keys
		c.Delegated = authkit.DelegatedConfig{Audiences: []string{"platform"}, AllowDPoP: true}
	}), authtest.WithDeps(func(d *authkit.Deps) { d.DelegatedAuthorization = authorizer }))
	a := newAPI(t, auth)
	u := authtest.NewUser(t, auth)
	session := authtest.SignIn(t, auth, u)
	browserKey := testdpop.Key(t)
	target := authtest.Issuer + "/api/v1/delegated/token"
	body := `{"requested_grant":{"permissions":["root:all"]},"audiences":["platform"],"ttl_seconds":1}`
	var lastChallenge string
	post := func(a *api, body, token, proof string, header http.Header) int {
		t.Helper()
		header = maps.Clone(header)
		if header == nil {
			header = http.Header{}
		}
		if proof != "" {
			header.Set("DPoP", proof)
		}
		res := a.do(request{method: http.MethodPost, path: "/delegated/token", body: body, token: token, header: header})
		lastChallenge = res.header.Get("WWW-Authenticate")
		return res.status
	}
	proofFor := func(target, token string) string {
		return testdpop.Proof(t, browserKey, http.MethodPost, target, token, nil)
	}

	// Neither Host nor forwarding headers select the proof target: it is the
	// issuer's own URL.
	evil := &api{t: t, prefix: a.prefix, h: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.Host = "evil.example"
		auth.Handler().ServeHTTP(w, r)
	})}
	proof := proofFor(target, session.AccessToken)
	res := evil.do(request{method: http.MethodPost, path: "/delegated/token", body: body, token: session.AccessToken, header: http.Header{
		"DPoP": {proof}, "Forwarded": {"host=evil.example;proto=http"}, "X-Forwarded-Host": {"evil.example"},
	}})
	require.Equal(t, http.StatusOK, res.status, res.String())
	var minted struct {
		Token     string `json:"token"`
		TokenType string `json:"token_type"`
	}
	res.decode(t, &minted)
	require.Equal(t, "DPoP", minted.TokenType)
	delegationGolden(t, "delegated-dpop-response", json.RawMessage(res.body))
	claims := delegatedClaims(t, minted.Token)
	delegationGolden(t, "delegated-dpop-claims", claims)
	mu.Lock()
	requestFacts := observed
	mu.Unlock()
	require.Equal(t, map[string]any{"jkt": jwtkit.CertificateThumbprint(*requestFacts.ConfirmationJWKThumbprintSHA256)}, claims["cnf"])
	require.Nil(t, requestFacts.DelegateCertificate)
	require.Equal(t, [32]byte{}, requestFacts.ConfirmationCertificateSHA256)
	require.Equal(t, u.ID, requestFacts.UserID)
	require.Equal(t, []any{"resource:read"}, claims["permissions"])
	require.Nil(t, claims["sub"])
	require.Equal(t, u.ID, claims["delegated_sub"])
	require.Equal(t, float64(60), claims["exp"].(float64)-claims["iat"].(float64))
	require.Equal(t, http.StatusUnauthorized, post(a, body, session.AccessToken, proof, nil))
	require.Equal(t, `DPoP error="invalid_dpop_proof", algs="ES256"`, lastChallenge)
	require.Equal(t, http.StatusBadRequest, post(a, body, session.AccessToken, "", nil))
	require.Equal(t, http.StatusUnauthorized, post(a, body, "", proofFor(target, ""), nil))
	require.Equal(t, http.StatusUnauthorized, post(a, body, session.AccessToken, proofFor(target, "wrong-parent"), nil))
	require.Equal(t, http.StatusBadRequest, post(a, delegationBody(newDelegateCertificate(t, nil), ""), session.AccessToken, proofFor(target, session.AccessToken), nil))
	require.Equal(t, http.StatusBadRequest, post(a, `{"audiences":["other"],"requested_grant":{}}`, session.AccessToken, proofFor(target, session.AccessToken), nil))
	require.EqualValues(t, 1, authorizations.Load())
	require.Equal(t, http.StatusForbidden, post(a, `{"requested_grant":{"refuse":true}}`, session.AccessToken, proofFor(target, session.AccessToken), nil))

	// A proxy may remove an external prefix. Its configured resolver supplies
	// that path explicitly.
	external := authtest.Issuer + "/external/api/v1/delegated/token"
	rewritten := newAPI(t, authtest.Replica(t, auth, authtest.WithConfig(func(c *authkit.Config) {
		c.HTTP.DPoPRequestURL = func(*http.Request) string { return external }
	})))
	require.Equal(t, http.StatusUnauthorized, post(rewritten, body, session.AccessToken, proofFor(target, session.AccessToken), nil))
	require.Equal(t, http.StatusOK, post(rewritten, body, session.AccessToken, proofFor(external, session.AccessToken), nil))

	// A receiver owns trusted URLs; NewVerifier shares the Client's replay
	// store, so one proof is spent once across every verifier.
	var resource *httptest.Server
	resourceURL := verify.WithDPoPRequestURL(func(r *http.Request) string { return resource.URL + r.URL.EscapedPath() })
	verifier := auth.NewVerifier(resourceURL)
	require.NoError(t, verifier.AddIssuer(authtest.Issuer, []string{"platform"}, verify.IssuerOptions{PublicKeys: keys.PublicKeys}))
	resourceMux := http.NewServeMux()
	resourceMux.Handle("/", delegatedResource(verifier))
	resourceMux.Handle("/required", verify.Required(verifier)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })))
	resource = httptest.NewTLSServer(resourceMux)
	t.Cleanup(resource.Close)
	call := func(scheme, token, proof, path string) int {
		req, err := http.NewRequest(http.MethodGet, resource.URL+path, nil)
		require.NoError(t, err)
		req.Header.Set("Authorization", scheme+" "+token)
		if proof != "" {
			req.Header.Set("DPoP", proof)
		}
		resp, err := resource.Client().Do(req)
		require.NoError(t, err)
		if resp.StatusCode == http.StatusUnauthorized {
			require.Equal(t, `DPoP error="invalid_dpop_proof", algs="ES256"`, resp.Header.Get("WWW-Authenticate"))
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		return resp.StatusCode
	}
	resourceProof := func(token string) string {
		return testdpop.Proof(t, browserKey, http.MethodGet, resource.URL+"/tasks", token, nil)
	}
	require.Equal(t, http.StatusOK, call("DPoP", minted.Token, resourceProof(minted.Token), "/tasks?cursor=next"))
	require.Equal(t, http.StatusUnauthorized, call("DPoP", minted.Token, resourceProof(minted.Token), "/required"))
	require.Equal(t, http.StatusOK, call("DPoP", minted.Token, testdpop.Proof(t, browserKey, http.MethodGet, resource.URL+"/required", minted.Token, nil), "/required"))
	require.Equal(t, http.StatusUnauthorized, call("Bearer", minted.Token, resourceProof(minted.Token), "/tasks"))
	require.Equal(t, http.StatusUnauthorized, call("DPoP", minted.Token, "", "/tasks"))
	require.Equal(t, http.StatusUnauthorized, call("DPoP", minted.Token, resourceProof("other-token"), "/tasks"))
	require.Equal(t, http.StatusUnauthorized, call("DPoP", minted.Token, resourceProof(minted.Token), "/other"))
	require.Equal(t, http.StatusUnauthorized, call("DPoP", minted.Token, testdpop.Proof(t, browserKey, http.MethodPost, resource.URL+"/tasks", minted.Token, nil), "/tasks"))
	require.Equal(t, http.StatusUnauthorized, call("DPoP", minted.Token, testdpop.Proof(t, testdpop.Key(t), http.MethodGet, resource.URL+"/tasks", minted.Token, nil), "/tasks"))
	_, err := verifier.Verify(ctx, minted.Token)
	require.ErrorIs(t, err, verify.ErrSenderProofRequired)
	detached, err := auth.MintDelegatedAccessToken(ctx, iam.UserActor(u.ID), iam.DelegatedAccess{Audiences: []string{"platform"}, Permissions: []string{"resource:read"}})
	require.NoError(t, err)
	require.Equal(t, http.StatusUnauthorized, call("DPoP", detached.Value, resourceProof(detached.Value), "/tasks"))
	certHash := [32]byte{1}
	_, err = auth.MintDelegatedAccessToken(ctx, iam.SystemActor(), iam.DelegatedAccess{Subject: u.ID, ConfirmationCertificateSHA256: &certHash, ConfirmationJWKThumbprintSHA256: requestFacts.ConfirmationJWKThumbprintSHA256})
	require.Error(t, err)
	oneProof := resourceProof(minted.Token)
	secondVerifier := auth.NewVerifier(resourceURL)
	require.NoError(t, secondVerifier.AddIssuer(authtest.Issuer, []string{"platform"}, verify.IssuerOptions{PublicKeys: keys.PublicKeys}))
	replayed := httptest.NewRequest(http.MethodGet, resource.URL+"/tasks", nil)
	replayed.Header.Set("Authorization", "DPoP "+minted.Token)
	replayed.Header.Set("DPoP", oneProof)
	_, err = secondVerifier.VerifyRequest(replayed)
	require.NoError(t, err, "the first use of a proof verifies")
	var successes atomic.Int32
	var wg sync.WaitGroup
	for range 12 {
		wg.Go(func() {
			if call("DPoP", minted.Token, oneProof, "/tasks") == http.StatusOK {
				successes.Add(1)
			}
		})
	}
	wg.Wait()
	require.Zero(t, successes.Load(), "a proof spent at another verifier is a replay")

	// Disabling DPoP protects existing native authorizers from nil certificates.
	native := newAPI(t, authtest.Replica(t, auth, authtest.WithConfig(func(c *authkit.Config) { c.Delegated.AllowDPoP = false })))
	require.Equal(t, http.StatusBadRequest, post(native, body, session.AccessToken, proofFor(target, session.AccessToken), nil))
}

// delegationHost is a host's delegation authorizer: it records each request
// and answers with grant, or refuses with refuse when set.
type delegationHost struct {
	mu       sync.Mutex
	requests []iam.DelegationRequest
	grant    iam.DelegationGrant
	refuse   error
}

func (h *delegationHost) authorize(_ context.Context, req iam.DelegationRequest) (iam.DelegationGrant, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.requests = append(h.requests, req)
	if h.refuse != nil {
		return iam.DelegationGrant{}, h.refuse
	}
	return h.grant, nil
}

func (h *delegationHost) seen() []iam.DelegationRequest {
	h.mu.Lock()
	defer h.mu.Unlock()
	return slices.Clone(h.requests)
}

func (h *delegationHost) answer(grant iam.DelegationGrant, refuse error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.grant, h.refuse = grant, refuse
}

// A delegated token minted over HTTP is bound to the delegate certificate
// and verifies only over mTLS with its key, until the issuer's signing key
// rotates and beyond.
func TestDelegatedTokenRoute_CertificateBoundEndToEnd(t *testing.T) {
	ctx := t.Context()
	keys := newSwappableKeySource(t, "bound-kid-1")
	delegate := newDelegateCertificate(t, nil)
	grant := iam.DelegationGrant{Permissions: []string{"resource:read"}, Attributes: map[string]any{"entitlement": "pro"}}
	host := &delegationHost{grant: grant}
	auth, _ := authtest.New(t, authtest.WithConfig(func(c *authkit.Config) {
		c.Keys.Source = keys
		c.Delegated = authkit.DelegatedConfig{Audiences: []string{"tensorhub.net", "other.example"}}
	}), authtest.WithDeps(func(d *authkit.Deps) { d.DelegatedAuthorization = host.authorize }))
	a := newAPI(t, auth)
	u := authtest.NewUser(t, auth)
	userToken := authtest.SignIn(t, auth, u).AccessToken
	mint := func(body, token string) response { return a.post("/delegated/token", token, body) }
	type minted struct {
		Token     string    `json:"token"`
		ExpiresAt time.Time `json:"expires_at"`
	}
	mintOK := func(body string) minted {
		t.Helper()
		res := mint(body, userToken)
		require.Equal(t, http.StatusOK, res.status, res.String())
		var m minted
		res.decode(t, &m)
		require.NotEmpty(t, m.Token)
		return m
	}

	// Unauthenticated mint is refused before the authorizer runs.
	require.Equal(t, http.StatusUnauthorized, mint(delegationBody(delegate, ""), "").status)
	require.Empty(t, host.seen())

	// Default mint: full audience list, default TTL, the authorizer's grant is
	// the complete signed authority, and the token bound to the delegate
	// certificate.
	res := mint(delegationBody(delegate, ""), userToken)
	require.Equal(t, http.StatusOK, res.status, res.String())
	var responseFields map[string]json.RawMessage
	res.decode(t, &responseFields)
	require.Len(t, responseFields, 2, "response is token + expires_at only: %s", res)
	var resp minted
	res.decode(t, &resp)

	requests := host.seen()
	require.Len(t, requests, 1)
	req := requests[0]
	require.Equal(t, u.ID, req.UserID)
	require.Equal(t, []string{"tensorhub.net", "other.example"}, req.Audiences)
	require.Equal(t, delegatedTTLDefault, req.TTL)
	require.Equal(t, jwtkit.CertificateSHA256(delegate.Leaf.Raw), req.ConfirmationCertificateSHA256)
	require.Equal(t, delegate.Leaf.Raw, req.DelegateCertificate.Raw)
	require.JSONEq(t, testRequestedGrant, string(req.RequestedGrant))

	claims := delegatedClaims(t, resp.Token)
	require.Equal(t, u.ID, claims["delegated_sub"])
	require.Nil(t, claims["sub"], "a delegated token never carries sub")
	require.Equal(t, authtest.Issuer, claims["iss"])
	require.ElementsMatch(t, []any{"tensorhub.net", "other.example"}, claims["aud"])
	require.Equal(t, map[string]any{"x5t#S256": jwtkit.CertificateThumbprintSHA256(delegate.Leaf.Raw)}, claims["cnf"])
	require.Equal(t, []any{"resource:read"}, claims["permissions"])
	attributes, ok := claims["attributes"].(map[string]any)
	require.True(t, ok)
	require.Equal(t, "pro", attributes["entitlement"])
	iat, exp := int64(claims["iat"].(float64)), int64(claims["exp"].(float64))
	require.Equal(t, int64(delegatedTTLDefault/time.Second), exp-iat, "default TTL")
	require.WithinDuration(t, time.Unix(exp, 0), resp.ExpiresAt, time.Second)

	// ak#270: revocable by id, fresh per mint.
	firstJTI, _ := claims["jti"].(string)
	_, err := uuid.Parse(firstJTI)
	require.NoError(t, err, "jti %q is not a uuid", firstJTI)
	require.NotEqual(t, firstJTI, delegatedClaims(t, mintOK(delegationBody(delegate, "")).Token)["jti"])

	// ---- Resource server: real mTLS round trip with the real verifier. ----
	signer := keys.ActiveSigner().(*jwtkit.RSASigner)
	ver := delegatedVerifier(t, signer, authtest.Issuer, []string{"tensorhub.net"})
	resource := mtlsResourceServer(t, ver)
	status, body := callResource(t, resourceClient(t, resource, &delegate.TLS), resource.URL, resp.Token, nil)
	require.Equal(t, http.StatusOK, status, body)
	require.Contains(t, body, `"bound":true`)
	require.Contains(t, body, u.ID)

	// A stolen token is useless without the certificate's private key.
	other := newDelegateCertificate(t, nil)
	spoof := map[string]string{"X-Client-Cert": delegate.encoded(), "X-Forwarded-Client-Cert": "Cert=" + delegate.encoded()}
	for name, attempt := range map[string]struct {
		cert    *tls.Certificate
		headers map[string]string
	}{
		"no client certificate":    {nil, nil},
		"another leaf":             {&other.TLS, nil},
		"spoofed headers, no cert": {nil, spoof},
	} {
		status, body := callResource(t, resourceClient(t, resource, attempt.cert), resource.URL, resp.Token, attempt.headers)
		require.Equal(t, http.StatusUnauthorized, status, name)
		require.Contains(t, body, "sender_proof_required", name)
	}
	plain := httptest.NewServer(delegatedResource(ver))
	t.Cleanup(plain.Close)
	status, body = callResource(t, plain.Client(), plain.URL, resp.Token, spoof)
	require.Equal(t, http.StatusUnauthorized, status)
	require.Contains(t, body, "sender_proof_required", "plain HTTP with spoofed certificate header")

	// Verification detached from its request fails closed.
	_, err = ver.Verify(ctx, resp.Token)
	require.ErrorIs(t, err, verify.ErrSenderProofRequired)
	_, _, err = ver.VerifyDelegatedAccess(ctx, resp.Token)
	require.ErrorIs(t, err, verify.ErrSenderProofRequired)

	// Wrong audience and wrong issuer fail closed even with the right leaf.
	narrow := mintOK(delegationBody(delegate, `"audiences":["tensorhub.net"]`))
	require.Equal(t, []any{"tensorhub.net"}, delegatedClaims(t, narrow.Token)["aud"])
	wrongAudience := mtlsResourceServer(t, delegatedVerifier(t, signer, authtest.Issuer, []string{"other.example"}))
	status, body = callResource(t, resourceClient(t, wrongAudience, &delegate.TLS), wrongAudience.URL, narrow.Token, nil)
	require.Equal(t, http.StatusUnauthorized, status)
	require.Contains(t, body, "bad_audience")
	wrongIssuer := mtlsResourceServer(t, delegatedVerifier(t, signer, "https://someone-else.example", []string{"tensorhub.net"}))
	status, body = callResource(t, resourceClient(t, wrongIssuer, &delegate.TLS), wrongIssuer.URL, narrow.Token, nil)
	require.Equal(t, http.StatusUnauthorized, status, body)
	require.NotContains(t, body, `"bound"`)

	// Trusted in-process minting stays unbound: a plain bearer over plain HTTP.
	unbound, err := auth.MintDelegatedAccessToken(ctx, iam.UserActor(u.ID), iam.DelegatedAccess{Audiences: []string{"tensorhub.net"}, TTL: time.Minute})
	require.NoError(t, err)
	status, body = callResource(t, plain.Client(), plain.URL, unbound.Value, nil)
	require.Equal(t, http.StatusOK, status, body)
	require.Contains(t, body, `"bound":false`)

	// ---- Mint-side clamps and rejections. ----
	badAud := mint(delegationBody(delegate, `"audiences":["evil.example"]`), userToken)
	require.Equal(t, http.StatusBadRequest, badAud.status)
	require.Contains(t, badAud.String(), "invalid_audiences")

	for requested, want := range map[int]int64{
		10:     int64(delegatedTTLFloor / time.Second),
		999999: int64(delegatedTTLCeiling / time.Second),
		600:    600,
	} {
		before := len(host.seen())
		c := delegatedClaims(t, mintOK(delegationBody(delegate, fmt.Sprintf(`"ttl_seconds":%d`, requested))).Token)
		require.Equal(t, want, int64(c["exp"].(float64))-int64(c["iat"].(float64)), "requested %d", requested)
		require.Equal(t, time.Duration(want)*time.Second, host.seen()[before].TTL, "authorizer sees the clamped TTL")
	}

	// Token expiry may not exceed the certificate's NotAfter.
	shortLived := newDelegateCertificate(t, func(c *x509.Certificate) { c.NotAfter = time.Now().Add(2 * time.Minute) })
	tooLong := mint(delegationBody(shortLived, ""), userToken)
	require.Equal(t, http.StatusBadRequest, tooLong.status)
	require.Contains(t, tooLong.String(), "ttl_exceeds_delegate_certificate")
	mintOK(delegationBody(shortLived, `"ttl_seconds":60`))

	badCertificate := map[string]string{
		"missing":       `{"requested_grant":{}}`,
		"malformed":     `{"delegate_certificate_der_b64url":"!!!","requested_grant":{}}`,
		"CA":            delegationBody(newDelegateCertificate(t, func(c *x509.Certificate) { c.IsCA = true }), ""),
		"expired":       delegationBody(newDelegateCertificate(t, func(c *x509.Certificate) { c.NotAfter = time.Now().Add(-time.Minute) }), ""),
		"no clientAuth": delegationBody(newDelegateCertificate(t, func(c *x509.Certificate) { c.ExtKeyUsage = nil }), ""),
		"oversized": delegationBody(newDelegateCertificate(t, func(c *x509.Certificate) {
			// Past the DER bound while still parseable.
			c.ExtraExtensions = append(c.ExtraExtensions, pkix.Extension{Id: asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 99999, 1}, Value: make([]byte, maxDelegateCertificateDER)})
		}), ""),
	}
	for name, body := range badCertificate {
		res := mint(body, userToken)
		require.Equal(t, http.StatusBadRequest, res.status, name)
		require.Contains(t, res.String(), "invalid_delegate_certificate", name)
	}
	badGrant := map[string]string{
		"missing":   `{"delegate_certificate_der_b64url":"` + delegate.encoded() + `"}`,
		"null":      `{"delegate_certificate_der_b64url":"` + delegate.encoded() + `","requested_grant":null}`,
		"array":     `{"delegate_certificate_der_b64url":"` + delegate.encoded() + `","requested_grant":[]}`,
		"string":    `{"delegate_certificate_der_b64url":"` + delegate.encoded() + `","requested_grant":"read"}`,
		"oversized": `{"delegate_certificate_der_b64url":"` + delegate.encoded() + `","requested_grant":{"pad":"` + strings.Repeat("a", maxRequestedGrantBytes) + `"}}`,
	}
	for name, body := range badGrant {
		res := mint(body, userToken)
		require.Equal(t, http.StatusBadRequest, res.status, name)
		require.Contains(t, res.String(), "invalid_requested_grant", name)
	}
	authorizerCalls := len(host.seen())

	// Client input never becomes authority: claim-shaped keys inside
	// requested_grant reach the host verbatim and the token carries only the
	// authorizer's grant; claim-shaped keys at the top level are unknown fields.
	injected := `{"permissions":["root:*"],"attributes":{"entitlement":"enterprise"},"documents":{"x/v1":"sha256:` + strings.Repeat("0", 64) + `"},"sub":"admin","delegated_sub":"admin","cnf":{"x5t#S256":"AAAA"},"exp":9999999999,"iss":"https://evil.example","jti":"chosen"}`
	c := delegatedClaims(t, mintOK(`{"delegate_certificate_der_b64url":"`+delegate.encoded()+`","requested_grant":`+injected+`}`).Token)
	requests = host.seen()
	require.JSONEq(t, injected, string(requests[len(requests)-1].RequestedGrant))
	require.Equal(t, []any{"resource:read"}, c["permissions"])
	require.Equal(t, "pro", c["attributes"].(map[string]any)["entitlement"])
	require.Nil(t, c["documents"])
	require.Nil(t, c["sub"])
	require.Equal(t, u.ID, c["delegated_sub"])
	require.Equal(t, authtest.Issuer, c["iss"])
	require.NotEqual(t, "chosen", c["jti"])
	require.Equal(t, map[string]any{"x5t#S256": jwtkit.CertificateThumbprintSHA256(delegate.Leaf.Raw)}, c["cnf"])
	require.Less(t, int64(c["exp"].(float64)), int64(9999999999))
	topLevel := mint(delegationBody(delegate, `"permissions":["root:*"]`), userToken)
	require.Equal(t, http.StatusBadRequest, topLevel.status)
	require.Contains(t, topLevel.String(), "invalid_request")
	require.Len(t, host.seen(), authorizerCalls+1, "rejected requests never reach the authorizer")

	// Host refusal produces no token; an authorizer outage is not a refusal.
	host.answer(grant, fmt.Errorf("policy: %w", iam.ErrDelegationRefused))
	refused := mint(delegationBody(delegate, ""), userToken)
	require.Equal(t, http.StatusForbidden, refused.status)
	require.Contains(t, refused.String(), "delegation_refused")
	require.NotContains(t, refused.String(), `"token"`)
	host.answer(grant, errors.New("entitlement store down"))
	outage := mint(delegationBody(delegate, ""), userToken)
	require.Equal(t, http.StatusServiceUnavailable, outage.status)
	require.Contains(t, outage.String(), "delegation_authorizer_unavailable")

	// Authorizer output is size-bounded: an unbounded grant never becomes a token.
	host.answer(iam.DelegationGrant{Attributes: map[string]any{"blob": strings.Repeat("a", maxDelegatedTokenBytes)}}, nil)
	huge := mint(delegationBody(delegate, ""), userToken)
	require.Equal(t, http.StatusInternalServerError, huge.status)
	var envelope iam.ErrorEnvelope
	huge.decode(t, &envelope)
	require.Equal(t, "internal_error", envelope.Error.Code, huge.String())
	require.NotEmpty(t, envelope.Error.Type)
	require.NotEmpty(t, envelope.Error.Message)

	// Construction guards: the route never mounts without its authorizer, and
	// an authorizer without a route is dead wiring.
	cfg, deps := bareConfig(t)
	cfg.HTTP = authkit.HTTPConfig{DirectPeerIP: true}
	cfg.Delegated = authkit.DelegatedConfig{Audiences: []string{"tensorhub.net"}}
	_, err = newClient(t, cfg, deps)
	require.ErrorContains(t, err, "Deps.DelegatedAuthorization")
	cfg.Delegated = authkit.DelegatedConfig{}
	deps.DelegatedAuthorization = host.authorize
	_, err = newClient(t, cfg, deps)
	require.ErrorContains(t, err, "Delegated.Audiences is empty")

	// A server with no Delegated config does not mount the route at all.
	bare := authtest.Replica(t, auth, authtest.WithConfig(func(c *authkit.Config) { c.Delegated = authkit.DelegatedConfig{} }),
		authtest.WithDeps(func(d *authkit.Deps) { d.DelegatedAuthorization = nil }))
	require.Equal(t, http.StatusNotFound, newAPI(t, bare).post("/delegated/token", userToken, delegationBody(delegate, "")).status)

	// A live key rotation (#238: the KeySource is read per operation): the
	// user's token from the old key keeps authenticating, the next mint signs
	// with the new key and still verifies as a delegated principal over mTLS.
	host.answer(iam.DelegationGrant{}, nil)
	keys.rotate(t, "bound-kid-2")
	rotated := mintOK(delegationBody(delegate, ""))
	kid, err := tokenKID(rotated.Token)
	require.NoError(t, err)
	require.Equal(t, "bound-kid-2", kid)
	rotatedResource := mtlsResourceServer(t, delegatedVerifier(t, keys.ActiveSigner().(*jwtkit.RSASigner), authtest.Issuer, []string{"tensorhub.net"}))
	status, body = callResource(t, resourceClient(t, rotatedResource, &delegate.TLS), rotatedResource.URL, rotated.Token, nil)
	require.Equal(t, http.StatusOK, status, body)
	require.Contains(t, body, u.ID)
}

// swappableKeySource is a live jwtkit.KeySource whose active signer rotates
// mid-test while every earlier public key stays served, as JWKS does during
// a rotation.
type swappableKeySource struct {
	mu     sync.Mutex
	active *jwtkit.RSASigner
	pubs   map[string]crypto.PublicKey
}

func newSwappableKeySource(t *testing.T, kid string) *swappableKeySource {
	t.Helper()
	signer, err := jwtkit.NewRSASigner(2048, kid)
	require.NoError(t, err)
	return &swappableKeySource{active: signer, pubs: map[string]crypto.PublicKey{kid: signer.PublicKey()}}
}

func (s *swappableKeySource) rotate(t *testing.T, kid string) {
	t.Helper()
	signer, err := jwtkit.NewRSASigner(2048, kid)
	require.NoError(t, err)
	s.mu.Lock()
	defer s.mu.Unlock()
	s.active = signer
	s.pubs[kid] = signer.PublicKey()
}

func (s *swappableKeySource) ActiveSigner() jwtkit.Signer {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.active
}

func (s *swappableKeySource) PublicKeys() map[string]crypto.PublicKey {
	s.mu.Lock()
	defer s.mu.Unlock()
	return maps.Clone(s.pubs)
}

// delegateCertificate is a self-signed client leaf a test presents over mTLS.
type delegateCertificate struct {
	Leaf *x509.Certificate
	TLS  tls.Certificate
}

func (c delegateCertificate) encoded() string {
	return base64.RawURLEncoding.EncodeToString(c.Leaf.Raw)
}

func newDelegateCertificate(t *testing.T, mutate func(*x509.Certificate)) delegateCertificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(now.UnixNano()),
		Subject:               pkix.Name{CommonName: "delegate"},
		NotBefore:             now.Add(-time.Minute),
		NotAfter:              now.Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}
	if mutate != nil {
		mutate(template)
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)
	leaf, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return delegateCertificate{Leaf: leaf, TLS: tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}}
}

const testRequestedGrant = `{"type":"example.read/v1","resources":["r1"]}`

// delegationBody is the canonical valid mint request for cert; extra adds
// fields.
func delegationBody(cert delegateCertificate, extra string) string {
	body := `{"delegate_certificate_der_b64url":"` + cert.encoded() + `","requested_grant":` + testRequestedGrant
	if extra != "" {
		body += "," + extra
	}
	return body + "}"
}

func delegatedClaims(t *testing.T, token string) jwt.MapClaims {
	t.Helper()
	claims := jwt.MapClaims{}
	_, _, err := jwt.NewParser().ParseUnverified(token, claims)
	require.NoError(t, err)
	return claims
}

// tokenKID is the kid protected header of a compact JWS.
func tokenKID(token string) (string, error) {
	header, _, ok := strings.Cut(token, ".")
	if !ok {
		return "", errors.New("token is not a compact JWS")
	}
	raw, err := base64.RawURLEncoding.DecodeString(header)
	if err != nil {
		return "", errors.New("token has a malformed protected header")
	}
	var h struct {
		KeyID string `json:"kid"`
	}
	if err := json.Unmarshal(raw, &h); err != nil || strings.TrimSpace(h.KeyID) == "" {
		return "", errors.New("token signing key id is unavailable")
	}
	return strings.TrimSpace(h.KeyID), nil
}

// delegatedVerifier is a resource server's Verifier trusting one issuer key.
func delegatedVerifier(t *testing.T, signer *jwtkit.RSASigner, iss string, aud []string) *verify.Verifier {
	t.Helper()
	v := verify.NewVerifier()
	require.NoError(t, v.AddIssuer(iss, aud, verify.IssuerOptions{RawKeys: map[string]crypto.PublicKey{signer.KID(): signer.PublicKey()}}))
	return v
}

// delegatedResource authenticates with ver and echoes the delegated principal.
func delegatedResource(ver *verify.Verifier) http.Handler {
	return verify.Required(ver)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cl, _ := verify.ClaimsFromContext(r.Context())
		principal, _ := cl.DelegatedAccess()
		_ = json.NewEncoder(w).Encode(map[string]any{
			"delegated_sub": principal.DelegatedSubject,
			"permissions":   principal.Permissions,
			"bound":         principal.ConfirmationCertificateSHA256 != nil,
		})
	}))
}

// mtlsResourceServer is a real TLS server that requests client certificates;
// Go's handshake proves possession of the presented leaf's private key.
func mtlsResourceServer(t *testing.T, ver *verify.Verifier) *httptest.Server {
	t.Helper()
	srv := httptest.NewUnstartedServer(delegatedResource(ver))
	srv.TLS = &tls.Config{ClientAuth: tls.RequestClientCert}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv
}

func resourceClient(t *testing.T, srv *httptest.Server, cert *tls.Certificate) *http.Client {
	t.Helper()
	transport := srv.Client().Transport.(*http.Transport).Clone()
	if cert != nil {
		transport.TLSClientConfig.Certificates = []tls.Certificate{*cert}
	}
	t.Cleanup(transport.CloseIdleConnections)
	return &http.Client{Transport: transport}
}

func callResource(t *testing.T, client *http.Client, url, token string, headers map[string]string) (int, string) {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, url, nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+token)
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := client.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	return resp.StatusCode, string(body)
}

// delegationGolden requires value to hold every documented field of the
// golden testdata/wire/<name>.json, with its type, allowing additive keys.
// Placeholders: $string (non-empty), $text, $number (positive), $strings.
func delegationGolden(t *testing.T, name string, value any) {
	t.Helper()
	fixture, err := os.ReadFile(filepath.Join("testdata", "wire", name+".json"))
	require.NoError(t, err)
	var expected, actual any
	require.NoError(t, json.Unmarshal(fixture, &expected))
	encoded, err := json.Marshal(value)
	require.NoError(t, err)
	require.NoError(t, json.Unmarshal(encoded, &actual))
	var match func(any, any, string)
	match = func(want, got any, path string) {
		switch want := want.(type) {
		case map[string]any:
			require.IsType(t, want, got, path)
			fields := got.(map[string]any)
			for key, value := range want {
				require.Contains(t, fields, key, path)
				match(value, fields[key], path+"."+key)
			}
		case string:
			switch want {
			case "$string":
				require.IsType(t, "", got, path)
				require.NotEmpty(t, got, path)
			case "$text":
				require.IsType(t, "", got, path)
			case "$number":
				require.IsType(t, float64(0), got, path)
				require.Greater(t, got.(float64), float64(0), path)
			case "$strings":
				require.IsType(t, []any{}, got, path)
				require.NotEmpty(t, got, path)
				for _, item := range got.([]any) {
					match("$string", item, path+"[]")
				}
			default:
				require.Equal(t, want, got, path)
			}
		case []any:
			// A single object is an item schema; scalar arrays pin exact values.
			if len(want) == 1 {
				if _, object := want[0].(map[string]any); object {
					require.IsType(t, []any{}, got, path)
					require.NotEmpty(t, got, path)
					for _, item := range got.([]any) {
						match(want[0], item, path+"[]")
					}
					return
				}
			}
			require.Equal(t, want, got, path)
		default:
			require.Equal(t, want, got, path)
		}
	}
	match(expected, actual, name)
}
