package authhttp

// ak#261 end-to-end over a real Postgres through the mounted handler: the
// config-declared audience allowlist + TTL clamps, the host-injected attribute
// provider (embedded.WithDelegatedAttributes), document-digest stamping from
// the wired providers (#260 pairing), and post-mint signing-KID
// reconciliation across a live key rotation. Skips without
// AUTHKIT_TEST_DATABASE_URL.

import (
	"context"
	"crypto"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	jwt "github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/open-rails/authkit/documents"
	"github.com/open-rails/authkit/embedded"
	"github.com/open-rails/authkit/jwtkit"
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

func TestDelegatedTokenRoute_EndToEnd(t *testing.T) {
	pool := newServerTestPool(t)
	ctx := context.Background()
	suffix := fmt.Sprintf("%d", time.Now().UnixNano())

	cfg := newServerTestConfig()
	cfg.Delegated = embedded.DelegatedConfig{Audiences: []string{"tensorhub.net", "other.example"}}
	cfg.Documents = embedded.DocumentsConfig{ReaderSlugs: []string{"tensorhub-" + suffix}}

	// The host-injected attribute provider (Paul's DI ruling): AuthKit calls
	// it with the authenticated user and stamps whatever comes back — in
	// cozy-art this will call openrails' ResolveEffectiveTier; here it is a
	// plain closure proving AuthKit never interprets the values.
	var providerCalls []string
	client := newServerClient(t, cfg, pool, embedded.WithDelegatedAttributes(
		func(_ context.Context, userID string) (map[string]any, map[string]string, error) {
			providerCalls = append(providerCalls, userID)
			return map[string]any{"entitlement": "pro"}, map[string]string{
				"example.host-doc/v1": documents.Digest([]byte("host-doc-" + suffix)),
			}, nil
		}))

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
	t.Cleanup(func() { _, _ = pool.Exec(context.Background(), `DELETE FROM profiles.users WHERE id = $1::uuid`, user.ID) })
	userToken, _, err := srv.svc.MintAccessToken(ctx, user.ID, nil)
	require.NoError(t, err)

	// Unauthenticated mint is refused.
	require.Equal(t, http.StatusUnauthorized, postDelegatedToken(h, `{}`, "").Code)

	// Default mint: full audience list, default TTL, provider attributes,
	// provider documents AND registered document digests stamped.
	rec := postDelegatedToken(h, `{}`, userToken)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	var resp struct {
		Token      string            `json:"token"`
		ExpiresAt  time.Time         `json:"expires_at"`
		Attributes map[string]any    `json:"attributes"`
		Documents  map[string]string `json:"documents"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
	require.Equal(t, []string{user.ID}, providerCalls, "provider is called once with the authenticated user")
	require.Equal(t, "pro", resp.Attributes["entitlement"])
	require.Equal(t, docSvc.Reference().Digest, resp.Documents[documentsTestType])

	claims := unverifiedClaims(t, resp.Token)
	require.Equal(t, user.ID, claims["delegated_sub"])
	require.Nil(t, claims["sub"], "a delegated token never carries sub")
	require.ElementsMatch(t, []any{"tensorhub.net", "other.example"}, claims["aud"])
	stamped, ok := claims["documents"].(map[string]any)
	require.True(t, ok, "documents claim missing: %v", claims)
	require.Equal(t, docSvc.Reference().Digest, stamped[documentsTestType])
	require.Equal(t, documents.Digest([]byte("host-doc-"+suffix)), stamped["example.host-doc/v1"],
		"host-provided per-user documents ride alongside registered providers")
	attributes, ok := claims["attributes"].(map[string]any)
	require.True(t, ok)
	require.Equal(t, "pro", attributes["entitlement"])
	iat, exp := int64(claims["iat"].(float64)), int64(claims["exp"].(float64))
	require.Equal(t, int64((15*time.Minute)/time.Second), exp-iat, "default TTL")

	// ak#270: the route's tokens are revocable by id — a jti is always
	// stamped and is fresh per mint, so a receiving service (tensorhub) can
	// deny a single delegated token instead of the whole session.
	firstJTI, _ := claims["jti"].(string)
	_, err = uuid.Parse(firstJTI)
	require.NoError(t, err, "jti %q is not a uuid", firstJTI)
	again := postDelegatedToken(h, `{}`, userToken)
	require.Equal(t, http.StatusOK, again.Code, again.Body.String())
	var reminted struct {
		Token string `json:"token"`
	}
	require.NoError(t, json.Unmarshal(again.Body.Bytes(), &reminted))
	require.NotEqual(t, firstJTI, unverifiedClaims(t, reminted.Token)["jti"],
		"a re-mint must not reuse the previous jti")

	// The stamped document is resolvable end-to-end by the configured reader.
	readerToken := registerDocumentReader(t, client, "tensorhub-"+suffix, "https://tensorhub-"+suffix+".example")
	served := getDocument(h, http.MethodGet, resp.Documents[documentsTestType], readerToken, nil)
	require.Equal(t, http.StatusOK, served.Code)

	// Audience-subset clamp.
	rec = postDelegatedToken(h, `{"audiences":["tensorhub.net"]}`, userToken)
	require.Equal(t, http.StatusOK, rec.Code)
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
	require.Equal(t, []any{"tensorhub.net"}, unverifiedClaims(t, resp.Token)["aud"].([]any))
	badAud := postDelegatedToken(h, `{"audiences":["evil.example"]}`, userToken)
	require.Equal(t, http.StatusBadRequest, badAud.Code)
	require.Contains(t, badAud.Body.String(), "invalid_audiences")

	// TTL clamps: below floor -> floor; above ceiling -> ceiling.
	for requested, want := range map[int]int64{
		10:     int64(embedded.DefaultDelegatedTTLFloor / time.Second),
		999999: int64(embedded.DefaultDelegatedTTLCeiling / time.Second),
		600:    600,
	} {
		rec = postDelegatedToken(h, fmt.Sprintf(`{"ttl_seconds":%d}`, requested), userToken)
		require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
		require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
		c := unverifiedClaims(t, resp.Token)
		require.Equal(t, want, int64(c["exp"].(float64))-int64(c["iat"].(float64)), "requested %d", requested)
	}

	// A server with no Delegated config does not mount the route at all.
	bare, err := NewServer(newServerClient(t, newServerTestConfig(), pool))
	require.NoError(t, err)
	bareHandler, err := MountHandler(bare, MountOptions{})
	require.NoError(t, err)
	require.Equal(t, http.StatusNotFound, postDelegatedToken(bareHandler, `{}`, userToken).Code)
}

func TestDelegatedTokenRoute_KIDRotationReconciliation(t *testing.T) {
	pool := newServerTestPool(t)
	ctx := context.Background()
	suffix := fmt.Sprintf("%d", time.Now().UnixNano())

	keySource := newSwappableKeySource(t, "rotate-kid-1")
	cfg := newServerTestConfig()
	cfg.Keys = embedded.KeysConfig{Source: keySource}
	cfg.Delegated = embedded.DelegatedConfig{Audiences: []string{"tensorhub.net"}}
	cfg.Documents = embedded.DocumentsConfig{ReaderSlugs: []string{"tensorhub-" + suffix}}
	client := newServerClient(t, cfg, pool)

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
	t.Cleanup(func() { _, _ = pool.Exec(context.Background(), `DELETE FROM profiles.users WHERE id = $1::uuid`, user.ID) })

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
	rec := postDelegatedToken(h, `{}`, userToken)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())

	// LIVE key rotation (#238: the Service reads the KeySource per-operation).
	// The user's EXISTING access token (kid-1, still in the served key set)
	// keeps authenticating; the next delegated mint signs with rotate-kid-2,
	// and the route's post-mint reconciliation must re-sign the persisted
	// document with the SAME digest.
	keySource.rotate(t, "rotate-kid-2")
	rec = postDelegatedToken(h, `{}`, userToken)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	var resp struct {
		Token     string            `json:"token"`
		Documents map[string]string `json:"documents"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
	kid, err := delegatedTokenSigningKID(resp.Token)
	require.NoError(t, err)
	require.Equal(t, "rotate-kid-2", kid)
	require.Equal(t, digest, resp.Documents[documentsTestType], "digest is stable across rotation repair")
	require.Equal(t, "rotate-kid-2", storedKID(), "stored artifact re-signed by the token's key")

	// The re-signed artifact still serves and still verifies as the same digest.
	readerToken := registerDocumentReader(t, client, "tensorhub-"+suffix, "https://tensorhub-"+suffix+".example")
	served := getDocument(h, http.MethodGet, digest, readerToken, nil)
	require.Equal(t, http.StatusOK, served.Code)
	_, err = documents.FromCompact(served.Body.String(), documents.Reference{Type: documentsTestType, Digest: digest})
	require.NoError(t, err)

	// And the minted token verifies as a delegated principal carrying the
	// stamped reference (the receiving-service side of the pairing).
	ver := newDelegatedVerifier(t, keySource.ActiveSigner().(*jwtkit.RSASigner), cfg.Token.Issuer, []string{"tensorhub.net"})
	verified, principal, err := ver.VerifyDelegatedAccess(resp.Token)
	require.NoError(t, err)
	require.Equal(t, user.ID, principal.DelegatedSubject)
	ref, ok := verified.DocumentReference(documentsTestType)
	require.True(t, ok)
	require.Equal(t, digest, ref.Digest)
}
