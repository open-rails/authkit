package authhttp

// ak#261/#277 end-to-end over a real Postgres through the mounted handler and
// a real mTLS resource server: the config-declared audience allowlist + TTL
// clamps, the host-injected delegation authorizer, RFC 8705 certificate
// binding (`cnf.x5t#S256`) proven against real TLS client certificates,
// document-digest stamping from the wired providers (#260 pairing), and
// post-mint signing-KID reconciliation across a live key rotation. Skips
// without AUTHKIT_TEST_DATABASE_URL.

import (
	"context"
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	jwt "github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	authkit "github.com/open-rails/authkit"
	"github.com/open-rails/authkit/documents"
	"github.com/open-rails/authkit/embedded"
	authcore "github.com/open-rails/authkit/internal/authcore"
	"github.com/open-rails/authkit/internal/testdb"
	"github.com/open-rails/authkit/jwtkit"
	"github.com/open-rails/authkit/verify"
)

// swappableKeySource is a live jwtkit.KeySource whose active signer can be
// rotated mid-test while every historical public key stays served (JWKS shape
// during rotation).
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
	out := make(map[string]crypto.PublicKey, len(s.pubs))
	for kid, key := range s.pubs {
		out[kid] = key
	}
	return out
}

func postDelegatedToken(h http.Handler, body, token string) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/api/v1/delegated/token", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	if token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}
	h.ServeHTTP(w, r)
	return w
}

func unverifiedClaims(t *testing.T, token string) jwt.MapClaims {
	t.Helper()
	claims := jwt.MapClaims{}
	_, _, err := jwt.NewParser().ParseUnverified(token, claims)
	require.NoError(t, err)
	return claims
}

const testRequestedGrant = `{"type":"example.read/v1","resources":["r1"]}`

// mintBody is the canonical valid mint request for cert; extra adds fields.
func mintBody(cert delegateCertificate, extra string) string {
	body := `{"delegate_certificate_der_b64url":"` + cert.encoded() + `","requested_grant":` + testRequestedGrant
	if extra != "" {
		body += "," + extra
	}
	return body + "}"
}

type mintResponse struct {
	Token     string    `json:"token"`
	ExpiresAt time.Time `json:"expires_at"`
}

func mintOK(t *testing.T, h http.Handler, body, userToken string) mintResponse {
	t.Helper()
	rec := postDelegatedToken(h, body, userToken)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	var resp mintResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
	require.NotEmpty(t, resp.Token)
	return resp
}

// resourceHandler authenticates with ver and echoes the delegated principal.
func resourceHandler(ver *verify.Verifier) http.Handler {
	return verify.Required(ver)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cl, _ := verify.ClaimsFromContext(r.Context())
		principal, _ := cl.DelegatedAccess()
		_ = json.NewEncoder(w).Encode(map[string]any{
			"delegated_sub": principal.DelegatedSubject,
			"permissions":   principal.Permissions,
			"documents":     principal.Documents,
			"bound":         principal.ConfirmationCertificateSHA256 != nil,
		})
	}))
}

// mtlsResourceServer is a real TLS server that requests client certificates;
// Go's handshake proves possession of the presented leaf's private key.
func mtlsResourceServer(t *testing.T, ver *verify.Verifier) *httptest.Server {
	t.Helper()
	srv := httptest.NewUnstartedServer(resourceHandler(ver))
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

func TestDelegatedTokenRoute_CertificateBoundEndToEnd(t *testing.T) {
	pool := testdb.Pool(t)
	ctx := context.Background()
	suffix := fmt.Sprintf("%d", time.Now().UnixNano())

	keySource := newSwappableKeySource(t, "bound-kid-1")
	cfg := newServerTestConfig()
	cfg.Keys = embedded.KeysConfig{Source: keySource}
	cfg.Delegated = embedded.DelegatedConfig{Audiences: []string{"tensorhub.net", "other.example"}}
	cfg.Documents = embedded.DocumentsConfig{Readers: []embedded.DocumentReader{{Issuer: "https://tensorhub-" + suffix + ".example"}}}

	delegate := newDelegateCertificate(t, nil)
	hostDocument := documents.Digest([]byte("host-doc-" + suffix))
	grant := authkit.DelegationGrant{
		Permissions: []string{"resource:read"},
		Attributes:  map[string]any{"entitlement": "pro"},
		Documents:   map[string]string{"example.host-doc/v1": hostDocument},
	}
	var requests []authkit.DelegationRequest
	var refuse error
	authorizer := func(_ context.Context, req authkit.DelegationRequest) (authkit.DelegationGrant, error) {
		requests = append(requests, req)
		if refuse != nil {
			return authkit.DelegationGrant{}, refuse
		}
		return grant, nil
	}
	client := newServerClient(t, cfg, pool, embedded.WithDelegatedAuthorization(authorizer))

	docSvc, err := documents.NewService(ctx, documents.ServiceConfig{
		Type:      documentsTestType,
		Payload:   json.RawMessage(`{"entitlements":{"pro":{}}}`),
		Issuer:    cfg.Token.Issuer,
		Audiences: cfg.Delegated.Audiences,
		Signer:    client,
		Store:     client.DocumentStore(),
	})
	require.NoError(t, err)
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM profiles.signed_documents WHERE digest = $1`, docSvc.Reference().Digest)
	})
	srv, err := NewServer(client, WithDocuments(docSvc))
	require.NoError(t, err)
	h, err := MountHandler(srv, MountOptions{})
	require.NoError(t, err)

	user, err := srv.svc.CreateUser(ctx, "delegated-"+suffix+"@test.example", "delegated"+suffix)
	require.NoError(t, err)
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM profiles.users WHERE id = $1::uuid`, user.ID)
	})
	userToken, _, err := srv.svc.MintAccessToken(ctx, user.ID, nil)
	require.NoError(t, err)

	// Unauthenticated mint is refused before the authorizer runs.
	require.Equal(t, http.StatusUnauthorized, postDelegatedToken(h, mintBody(delegate, ""), "").Code)
	require.Empty(t, requests)

	// Default mint: full audience list, default TTL, the authorizer's grant is
	// the complete signed authority, provider documents stamped alongside it,
	// and the token bound to the delegate certificate.
	rec := postDelegatedToken(h, mintBody(delegate, ""), userToken)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	var responseFields map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &responseFields))
	require.Len(t, responseFields, 2, "response is token + expires_at only: %s", rec.Body.String())
	var resp mintResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))

	require.Len(t, requests, 1)
	req := requests[0]
	require.Equal(t, user.ID, req.UserID)
	require.Equal(t, []string{"tensorhub.net", "other.example"}, req.Audiences)
	require.Equal(t, authcore.DefaultDelegatedTTLDefault, req.TTL)
	require.Equal(t, jwtkit.CertificateSHA256(delegate.Leaf.Raw), req.ConfirmationCertificateSHA256)
	require.Equal(t, delegate.Leaf.Raw, req.DelegateCertificate.Raw)
	require.JSONEq(t, testRequestedGrant, string(req.RequestedGrant))

	claims := unverifiedClaims(t, resp.Token)
	require.Equal(t, user.ID, claims["delegated_sub"])
	require.Nil(t, claims["sub"], "a delegated token never carries sub")
	require.Equal(t, cfg.Token.Issuer, claims["iss"])
	require.ElementsMatch(t, []any{"tensorhub.net", "other.example"}, claims["aud"])
	require.Equal(t, map[string]any{"x5t#S256": jwtkit.CertificateThumbprintSHA256(delegate.Leaf.Raw)}, claims["cnf"])
	require.Equal(t, []any{"resource:read"}, claims["permissions"])
	attributes, ok := claims["attributes"].(map[string]any)
	require.True(t, ok)
	require.Equal(t, "pro", attributes["entitlement"])
	stamped, ok := claims["documents"].(map[string]any)
	require.True(t, ok, "documents claim missing: %v", claims)
	require.Equal(t, docSvc.Reference().Digest, stamped[documentsTestType])
	require.Equal(t, hostDocument, stamped["example.host-doc/v1"], "authorizer documents ride alongside registered providers")
	iat, exp := int64(claims["iat"].(float64)), int64(claims["exp"].(float64))
	require.Equal(t, int64(authcore.DefaultDelegatedTTLDefault/time.Second), exp-iat, "default TTL")
	require.WithinDuration(t, time.Unix(exp, 0), resp.ExpiresAt, time.Second)

	// ak#270: revocable by id, fresh per mint.
	firstJTI, _ := claims["jti"].(string)
	_, err = uuid.Parse(firstJTI)
	require.NoError(t, err, "jti %q is not a uuid", firstJTI)
	require.NotEqual(t, firstJTI, unverifiedClaims(t, mintOK(t, h, mintBody(delegate, ""), userToken).Token)["jti"])

	// The stamped document is resolvable end-to-end by the configured reader.
	readerToken := registerDocumentReader(t, client, "tensorhub-"+suffix, "https://tensorhub-"+suffix+".example")
	require.Equal(t, http.StatusOK, getDocument(h, http.MethodGet, docSvc.Reference().Digest, readerToken, nil).Code)

	// ---- Resource server: real mTLS round trip with the real verifier. ----
	signer := keySource.ActiveSigner().(*jwtkit.RSASigner)
	ver := newDelegatedVerifier(t, signer, cfg.Token.Issuer, []string{"tensorhub.net"})
	resource := mtlsResourceServer(t, ver)
	status, body := callResource(t, resourceClient(t, resource, &delegate.TLS), resource.URL, resp.Token, nil)
	require.Equal(t, http.StatusOK, status, body)
	require.Contains(t, body, `"bound":true`)
	require.Contains(t, body, user.ID)
	require.Contains(t, body, docSvc.Reference().Digest)

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
	plain := httptest.NewServer(resourceHandler(ver))
	t.Cleanup(plain.Close)
	status, body = callResource(t, plain.Client(), plain.URL, resp.Token, spoof)
	require.Equal(t, http.StatusUnauthorized, status)
	require.Contains(t, body, "sender_proof_required", "plain HTTP with spoofed certificate header")

	// Verification detached from its request fails closed.
	_, err = ver.Verify(context.Background(), resp.Token)
	require.ErrorIs(t, err, verify.ErrSenderProofRequired)
	_, _, err = ver.VerifyDelegatedAccess(context.Background(), resp.Token)
	require.ErrorIs(t, err, verify.ErrSenderProofRequired)

	// Wrong audience and wrong issuer fail closed even with the right leaf.
	narrow := mintOK(t, h, mintBody(delegate, `"audiences":["tensorhub.net"]`), userToken)
	require.Equal(t, []any{"tensorhub.net"}, unverifiedClaims(t, narrow.Token)["aud"])
	wrongAudience := mtlsResourceServer(t, newDelegatedVerifier(t, signer, cfg.Token.Issuer, []string{"other.example"}))
	status, body = callResource(t, resourceClient(t, wrongAudience, &delegate.TLS), wrongAudience.URL, narrow.Token, nil)
	require.Equal(t, http.StatusUnauthorized, status)
	require.Contains(t, body, "bad_audience")
	wrongIssuer := mtlsResourceServer(t, newDelegatedVerifier(t, signer, "https://someone-else.example", []string{"tensorhub.net"}))
	status, body = callResource(t, resourceClient(t, wrongIssuer, &delegate.TLS), wrongIssuer.URL, narrow.Token, nil)
	require.Equal(t, http.StatusUnauthorized, status, body)
	require.NotContains(t, body, `"bound"`)

	// Trusted in-process minting stays unbound: a plain bearer over plain HTTP.
	unbound, err := embedded.Unwrap(client).MintDelegatedAccessToken(ctx, authkit.DelegatedAccessParams{
		Audiences: []string{"tensorhub.net"}, DelegatedSubject: user.ID, TTL: time.Minute,
	})
	require.NoError(t, err)
	status, body = callResource(t, plain.Client(), plain.URL, unbound, nil)
	require.Equal(t, http.StatusOK, status, body)
	require.Contains(t, body, `"bound":false`)

	// ---- Mint-side clamps and rejections. ----
	badAud := postDelegatedToken(h, mintBody(delegate, `"audiences":["evil.example"]`), userToken)
	require.Equal(t, http.StatusBadRequest, badAud.Code)
	require.Contains(t, badAud.Body.String(), "invalid_audiences")

	for requested, want := range map[int]int64{
		10:     int64(authcore.DefaultDelegatedTTLFloor / time.Second),
		999999: int64(authcore.DefaultDelegatedTTLCeiling / time.Second),
		600:    600,
	} {
		before := len(requests)
		c := unverifiedClaims(t, mintOK(t, h, mintBody(delegate, fmt.Sprintf(`"ttl_seconds":%d`, requested)), userToken).Token)
		require.Equal(t, want, int64(c["exp"].(float64))-int64(c["iat"].(float64)), "requested %d", requested)
		require.Equal(t, time.Duration(want)*time.Second, requests[before].TTL, "authorizer sees the clamped TTL")
	}

	// Token expiry may not exceed the certificate's NotAfter.
	shortLived := newDelegateCertificate(t, func(c *x509.Certificate) { c.NotAfter = time.Now().Add(2 * time.Minute) })
	tooLong := postDelegatedToken(h, mintBody(shortLived, ""), userToken)
	require.Equal(t, http.StatusBadRequest, tooLong.Code)
	require.Contains(t, tooLong.Body.String(), "ttl_exceeds_delegate_certificate")
	mintOK(t, h, mintBody(shortLived, `"ttl_seconds":60`), userToken)

	badCertificate := map[string]string{
		"missing":       `{"requested_grant":{}}`,
		"malformed":     `{"delegate_certificate_der_b64url":"!!!","requested_grant":{}}`,
		"CA":            mintBody(newDelegateCertificate(t, func(c *x509.Certificate) { c.IsCA = true }), ""),
		"expired":       mintBody(newDelegateCertificate(t, func(c *x509.Certificate) { c.NotAfter = time.Now().Add(-time.Minute) }), ""),
		"no clientAuth": mintBody(newDelegateCertificate(t, func(c *x509.Certificate) { c.ExtKeyUsage = nil }), ""),
		"oversized": mintBody(newDelegateCertificate(t, func(c *x509.Certificate) {
			c.ExtraExtensions = append(c.ExtraExtensions, oversizedExtension())
		}), ""),
	}
	for name, body := range badCertificate {
		rec := postDelegatedToken(h, body, userToken)
		require.Equal(t, http.StatusBadRequest, rec.Code, name)
		require.Contains(t, rec.Body.String(), "invalid_delegate_certificate", name)
	}
	badGrant := map[string]string{
		"missing":   `{"delegate_certificate_der_b64url":"` + delegate.encoded() + `"}`,
		"null":      `{"delegate_certificate_der_b64url":"` + delegate.encoded() + `","requested_grant":null}`,
		"array":     `{"delegate_certificate_der_b64url":"` + delegate.encoded() + `","requested_grant":[]}`,
		"string":    `{"delegate_certificate_der_b64url":"` + delegate.encoded() + `","requested_grant":"read"}`,
		"oversized": `{"delegate_certificate_der_b64url":"` + delegate.encoded() + `","requested_grant":{"pad":"` + strings.Repeat("a", maxRequestedGrantBytes) + `"}}`,
	}
	for name, body := range badGrant {
		rec := postDelegatedToken(h, body, userToken)
		require.Equal(t, http.StatusBadRequest, rec.Code, name)
		require.Contains(t, rec.Body.String(), "invalid_requested_grant", name)
	}
	authorizerCalls := len(requests)

	// Client input never becomes authority: claim-shaped keys inside
	// requested_grant reach the host verbatim and the token carries only the
	// authorizer's grant; claim-shaped keys at the top level are unknown fields.
	injected := `{"permissions":["root:*"],"attributes":{"entitlement":"enterprise"},"documents":{"x/v1":"sha256:` + strings.Repeat("0", 64) + `"},"sub":"admin","delegated_sub":"admin","cnf":{"x5t#S256":"AAAA"},"exp":9999999999,"iss":"https://evil.example","jti":"chosen"}`
	c := unverifiedClaims(t, mintOK(t, h, `{"delegate_certificate_der_b64url":"`+delegate.encoded()+`","requested_grant":`+injected+`}`, userToken).Token)
	require.JSONEq(t, injected, string(requests[len(requests)-1].RequestedGrant))
	require.Equal(t, []any{"resource:read"}, c["permissions"])
	require.Equal(t, "pro", c["attributes"].(map[string]any)["entitlement"])
	require.Nil(t, c["documents"].(map[string]any)["x/v1"])
	require.Nil(t, c["sub"])
	require.Equal(t, user.ID, c["delegated_sub"])
	require.Equal(t, cfg.Token.Issuer, c["iss"])
	require.NotEqual(t, "chosen", c["jti"])
	require.Equal(t, map[string]any{"x5t#S256": jwtkit.CertificateThumbprintSHA256(delegate.Leaf.Raw)}, c["cnf"])
	require.Less(t, int64(c["exp"].(float64)), int64(9999999999))
	topLevel := postDelegatedToken(h, mintBody(delegate, `"permissions":["root:*"]`), userToken)
	require.Equal(t, http.StatusBadRequest, topLevel.Code)
	require.Contains(t, topLevel.Body.String(), "invalid_request")
	require.Len(t, requests, authorizerCalls+1, "rejected requests never reach the authorizer")

	// Host refusal produces no token; an authorizer outage is not a refusal.
	refuse = fmt.Errorf("policy: %w", authkit.ErrDelegationRefused)
	refused := postDelegatedToken(h, mintBody(delegate, ""), userToken)
	require.Equal(t, http.StatusForbidden, refused.Code)
	require.Contains(t, refused.Body.String(), "delegation_refused")
	require.NotContains(t, refused.Body.String(), `"token"`)
	refuse = errors.New("entitlement store down")
	outage := postDelegatedToken(h, mintBody(delegate, ""), userToken)
	require.Equal(t, http.StatusServiceUnavailable, outage.Code)
	require.Contains(t, outage.Body.String(), "delegation_authorizer_unavailable")
	refuse = nil

	// Authorizer output is size-bounded: an unbounded grant never becomes a token.
	grant = authkit.DelegationGrant{Attributes: map[string]any{"blob": strings.Repeat("a", maxDelegatedTokenBytes)}}
	huge := postDelegatedToken(h, mintBody(delegate, ""), userToken)
	require.Equal(t, http.StatusInternalServerError, huge.Code)
	require.Contains(t, huge.Body.String(), "delegated_token_too_large")

	// A host document colliding with a registered provider's type on another
	// digest is a wiring bug and fails loudly.
	grant = authkit.DelegationGrant{Documents: map[string]string{documentsTestType: documents.Digest([]byte("stale-" + suffix))}}
	collision := postDelegatedToken(h, mintBody(delegate, ""), userToken)
	require.Equal(t, http.StatusServiceUnavailable, collision.Code)
	require.Contains(t, collision.Body.String(), "delegated_document_unavailable")

	// Construction guards: the route never mounts without its authorizer, and
	// an authorizer without a route is dead wiring.
	noAuthorizer := newServerTestConfig()
	noAuthorizer.Delegated = embedded.DelegatedConfig{Audiences: []string{"tensorhub.net"}}
	_, err = NewServer(newServerClient(t, noAuthorizer, pool))
	require.ErrorContains(t, err, "WithDelegatedAuthorization")
	_, err = NewServer(newServerClient(t, newServerTestConfig(), pool, embedded.WithDelegatedAuthorization(authorizer)))
	require.ErrorContains(t, err, "Delegated.Audiences is empty")

	// A server with no Delegated config does not mount the route at all.
	bare, err := NewServer(newServerClient(t, newServerTestConfig(), pool))
	require.NoError(t, err)
	bareHandler, err := MountHandler(bare, MountOptions{})
	require.NoError(t, err)
	require.Equal(t, http.StatusNotFound, postDelegatedToken(bareHandler, mintBody(delegate, ""), userToken).Code)
}

func TestDelegatedTokenRoute_KIDRotationReconciliation(t *testing.T) {
	pool := testdb.Pool(t)
	ctx := context.Background()
	suffix := fmt.Sprintf("%d", time.Now().UnixNano())

	keySource := newSwappableKeySource(t, "rotate-kid-1")
	cfg := newServerTestConfig()
	cfg.Keys = embedded.KeysConfig{Source: keySource}
	cfg.Delegated = embedded.DelegatedConfig{Audiences: []string{"tensorhub.net"}}
	cfg.Documents = embedded.DocumentsConfig{Readers: []embedded.DocumentReader{{Issuer: "https://tensorhub-" + suffix + ".example"}}}
	client := newServerClient(t, cfg, pool, embedded.WithDelegatedAuthorization(
		func(context.Context, authkit.DelegationRequest) (authkit.DelegationGrant, error) {
			return authkit.DelegationGrant{}, nil
		}))

	docSvc, err := documents.NewService(ctx, documents.ServiceConfig{
		Type:      documentsTestType,
		Payload:   json.RawMessage(fmt.Sprintf(`{"rotation":%q}`, suffix)),
		Issuer:    cfg.Token.Issuer,
		Audiences: cfg.Delegated.Audiences,
		Signer:    client,
		Store:     client.DocumentStore(),
	})
	require.NoError(t, err)
	digest := docSvc.Reference().Digest
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM profiles.signed_documents WHERE digest = $1`, digest)
	})
	srv, err := NewServer(client, WithDocuments(docSvc))
	require.NoError(t, err)
	h, err := MountHandler(srv, MountOptions{})
	require.NoError(t, err)

	user, err := srv.svc.CreateUser(ctx, "rotate-"+suffix+"@test.example", "rotate"+suffix)
	require.NoError(t, err)
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM profiles.users WHERE id = $1::uuid`, user.ID)
	})
	delegate := newDelegateCertificate(t, nil)

	storedKID := func() string {
		t.Helper()
		document, err := docSvc.Lookup(ctx, digest)
		require.NoError(t, err)
		header, _, err := documents.DecodeCompact(document.CompactJWS)
		require.NoError(t, err)
		return header.KeyID
	}
	require.Equal(t, "rotate-kid-1", storedKID())

	// Mint before rotation: artifact already matches the token key.
	userToken, _, err := srv.svc.MintAccessToken(ctx, user.ID, nil)
	require.NoError(t, err)
	mintOK(t, h, mintBody(delegate, ""), userToken)

	// LIVE key rotation (#238: the Service reads the KeySource per-operation).
	// The user's EXISTING access token (kid-1, still in the served key set)
	// keeps authenticating; the next delegated mint signs with rotate-kid-2,
	// and the route's post-mint reconciliation must re-sign the persisted
	// document with the SAME digest.
	keySource.rotate(t, "rotate-kid-2")
	resp := mintOK(t, h, mintBody(delegate, ""), userToken)
	kid, err := delegatedTokenSigningKID(resp.Token)
	require.NoError(t, err)
	require.Equal(t, "rotate-kid-2", kid)
	require.Equal(t, digest, unverifiedClaims(t, resp.Token)["documents"].(map[string]any)[documentsTestType], "digest is stable across rotation repair")
	require.Equal(t, "rotate-kid-2", storedKID(), "stored artifact re-signed by the token's key")

	// The re-signed artifact still serves and still verifies as the same digest.
	readerToken := registerDocumentReader(t, client, "tensorhub-"+suffix, "https://tensorhub-"+suffix+".example")
	served := getDocument(h, http.MethodGet, digest, readerToken, nil)
	require.Equal(t, http.StatusOK, served.Code)
	_, err = documents.FromCompact(served.Body.String(), documents.Reference{Type: documentsTestType, Digest: digest})
	require.NoError(t, err)

	// And the minted token verifies over mTLS as a delegated principal carrying
	// the stamped reference (the receiving-service side of the pairing).
	ver := newDelegatedVerifier(t, keySource.ActiveSigner().(*jwtkit.RSASigner), cfg.Token.Issuer, []string{"tensorhub.net"})
	resource := mtlsResourceServer(t, ver)
	status, body := callResource(t, resourceClient(t, resource, &delegate.TLS), resource.URL, resp.Token, nil)
	require.Equal(t, http.StatusOK, status, body)
	require.Contains(t, body, user.ID)
	require.Contains(t, body, digest)
}
