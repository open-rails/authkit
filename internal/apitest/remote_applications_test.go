package apitest_test

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"net/http"
	"net/url"
	"testing"
	"time"

	jwt "github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/open-rails/authkit/authtest"
	"github.com/open-rails/authkit/iam"
)

// TestGroupRemoteApplicationRoutes: a group's credential manager registers
// its backend's signing key over HTTP; the RFC 7523 grant accepts that
// backend's assertion, disabling the application refuses it and deleting it
// removes it. Another group's application is 404 here, an issuer registered
// already is a conflict, and an API key registers nothing.
func TestGroupRemoteApplicationRoutes(t *testing.T) {
	s := newShop(t)
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	require.NoError(t, err)
	keyPEM := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
	const issuer = "https://shop.example"
	apps := s.path(s.a, "/remote-applications")

	type pubKey struct {
		KID          string  `json:"kid"`
		PublicKeyPEM *string `json:"public_key_pem"`
	}
	type app struct {
		ID         string   `json:"id"`
		GroupID    string   `json:"group_id"`
		Issuer     string   `json:"issuer"`
		Mode       string   `json:"mode"`
		JWKSURI    *string  `json:"jwks_uri"`
		PublicKeys []pubKey `json:"public_keys"`
		Enabled    bool     `json:"enabled"`
		TrustRoot  string   `json:"trust_root"`
	}
	var shop app
	expect(t, http.StatusCreated, s.api.post(apps, s.ownerToken, map[string]any{
		"issuer": issuer, "public_keys": []map[string]string{{"kid": "k1", "public_key_pem": keyPEM}},
	})).decode(t, &shop)
	require.Equal(t, app{ID: shop.ID, GroupID: s.a.ID(), Issuer: issuer, Mode: "static", Enabled: true, TrustRoot: "user",
		PublicKeys: []pubKey{{KID: "k1", PublicKeyPEM: &keyPEM}}}, shop)
	var page struct {
		Data []app `json:"data"`
	}
	expect(t, http.StatusOK, s.api.get(apps, s.ownerToken)).decode(t, &page)
	require.Equal(t, []app{shop}, page.Data)
	res := s.api.post(apps, s.ownerToken, map[string]any{"issuer": issuer, "jwks_uri": issuer + "/jwks.json"})
	require.Equal(t, http.StatusConflict, res.status, res.String())
	require.Equal(t, "remote_application_issuer_conflict", res.code())

	redeem := func() int {
		now := time.Now()
		tok := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{"iss": issuer, "sub": "customer-42",
			"aud": authtest.Issuer + iam.OAuthTokenPath, "jti": uuid.NewString(), "iat": now.Unix(), "exp": now.Add(time.Minute).Unix()})
		tok.Header["kid"] = "k1"
		assertion, err := tok.SignedString(key)
		require.NoError(t, err)
		form := url.Values{"grant_type": {"urn:ietf:params:oauth:grant-type:jwt-bearer"}, "assertion": {assertion}}
		return s.api.do(request{method: http.MethodPost, path: "/" + iam.OAuthTokenPath, body: form.Encode(),
			header: http.Header{"Content-Type": {"application/x-www-form-urlencoded"}}}).status
	}
	require.Equal(t, http.StatusOK, redeem(), "the registered backend's assertion")

	one := apps + "/" + shop.ID
	var disabled app
	expect(t, http.StatusOK, s.api.do(request{method: http.MethodPatch, path: one, token: s.ownerToken,
		body: map[string]any{"enabled": false}})).decode(t, &disabled)
	require.False(t, disabled.Enabled)
	require.Equal(t, shop.PublicKeys, disabled.PublicKeys, "the keys it did not name are kept")
	require.NotEqual(t, http.StatusOK, redeem(), "a disabled application's assertion")
	expect(t, http.StatusOK, s.api.do(request{method: http.MethodPatch, path: one, token: s.ownerToken,
		body: map[string]any{"enabled": true}}))
	require.Equal(t, http.StatusOK, redeem())

	// Group b's application is not group a's to read or change.
	otherToken := authtest.SignIn(t, s.auth, s.other).AccessToken
	var theirs app
	expect(t, http.StatusCreated, s.api.post(s.path(s.b, "/remote-applications"), otherToken, map[string]any{
		"issuer": "https://other.example", "jwks_uri": "https://other.example/jwks.json",
	})).decode(t, &theirs)
	for _, method := range []string{http.MethodPatch, http.MethodDelete} {
		res := s.api.do(request{method: method, path: apps + "/" + theirs.ID, token: s.ownerToken, body: map[string]any{"enabled": false}})
		require.Equal(t, http.StatusNotFound, res.status, "%s: %s", method, res)
		require.Equal(t, "remote_application_not_found", res.code())
	}
	expect(t, http.StatusOK, s.api.get(apps, s.ownerToken)).decode(t, &page)
	require.Equal(t, []string{shop.ID}, []string{page.Data[0].ID})
	require.Len(t, page.Data, 1)

	// Only a person registers a backend's keys.
	ops, err := s.auth.CreateAPIKey(t.Context(), iam.SystemIdentity(), s.a, iam.NewAPIKey{Name: "ops", Role: s.manager})
	require.NoError(t, err)
	res = s.api.post(apps, ops.Secret, map[string]any{"issuer": "https://ops.example", "jwks_uri": "https://ops.example/jwks.json"})
	require.Equal(t, http.StatusForbidden, res.status, res.String())

	expect(t, http.StatusNoContent, s.api.do(request{method: http.MethodDelete, path: one, token: s.ownerToken}))
	expect(t, http.StatusOK, s.api.get(apps, s.ownerToken)).decode(t, &page)
	require.Empty(t, page.Data)
	require.NotEqual(t, http.StatusOK, redeem(), "a deleted application's assertion")
}
