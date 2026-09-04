package verify

// ak#277: RFC 8705 certificate-bound delegated tokens. The peer certificate
// comes ONLY from the request's TLS state; the real handshake round trip lives
// in authhttp's integration test, this pins the verifier's fail-closed matrix.

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	jwt "github.com/golang-jwt/jwt/v5"
	"github.com/open-rails/authkit/jwtkit"
)

const confirmationIssuer = "https://issuer.example"

func confirmationLeaf(t *testing.T) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(now.UnixNano()),
		Subject:               pkix.Name{CommonName: "delegate"},
		NotBefore:             now.Add(-time.Minute),
		NotAfter:              now.Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return leaf
}

func confirmationVerifier(t *testing.T) (*Verifier, *jwtkit.RSASigner) {
	t.Helper()
	signer, err := jwtkit.NewRSASigner(2048, "cnf-kid")
	if err != nil {
		t.Fatal(err)
	}
	v := NewVerifier()
	if err := v.AddIssuer(confirmationIssuer, []string{"resource"}, IssuerOptions{
		RawKeys: map[string]crypto.PublicKey{signer.KID(): signer.PublicKey()},
	}); err != nil {
		t.Fatal(err)
	}
	return v, signer
}

func delegatedClaims(extra map[string]any) jwt.MapClaims {
	now := time.Now()
	claims := jwt.MapClaims{
		"iss": confirmationIssuer, "aud": []string{"resource"}, "iat": now.Unix(),
		"exp": now.Add(time.Minute).Unix(), "delegated_sub": "user-1", "jti": "token-1",
	}
	for k, v := range extra {
		claims[k] = v
	}
	return claims
}

func signTyped(t *testing.T, signer *jwtkit.RSASigner, typ string, claims jwt.MapClaims) string {
	t.Helper()
	token, err := signer.SignWithHeaders(context.Background(), claims, map[string]any{"typ": typ})
	if err != nil {
		t.Fatal(err)
	}
	return token
}

// signDelegatedPayload signs an exact payload so duplicate keys survive.
func signDelegatedPayload(t *testing.T, signer *jwtkit.RSASigner, cnf string) string {
	t.Helper()
	now := time.Now()
	payload := fmt.Sprintf(`{"iss":%q,"aud":["resource"],"iat":%d,"exp":%d,"delegated_sub":"user-1","jti":"token-1",%s}`,
		confirmationIssuer, now.Unix(), now.Add(time.Minute).Unix(), cnf)
	token, err := signer.SignPayload(context.Background(), []byte(payload), map[string]any{"typ": DelegatedAccessTokenType})
	if err != nil {
		t.Fatal(err)
	}
	return token
}

func peerRequest(token string, peer *x509.Certificate) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "/resource", nil)
	r.Header.Set("Authorization", "Bearer "+token)
	if peer != nil {
		r.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{peer}}
	}
	return r
}

func requireReason(t *testing.T, err error, want string, context string) {
	t.Helper()
	if err == nil || err.Error() != want {
		t.Fatalf("%s: want %s, got %v", context, want, err)
	}
}

func TestCertificateBoundDelegatedToken_RequiresExactPeer(t *testing.T) {
	v, signer := confirmationVerifier(t)
	leaf, other := confirmationLeaf(t), confirmationLeaf(t)
	sum := jwtkit.CertificateSHA256(leaf.Raw)
	token := signTyped(t, signer, DelegatedAccessTokenType, delegatedClaims(map[string]any{"cnf": jwtkit.ConfirmationClaimValue(sum)}))

	// Detached from a request: no proof can exist.
	if _, err := v.Verify(token); !errors.Is(err, ErrSenderProofRequired) {
		t.Fatalf("token-only Verify: %v", err)
	}
	if _, _, err := v.VerifyDelegatedAccess(token); !errors.Is(err, ErrSenderProofRequired) {
		t.Fatalf("token-only VerifyDelegatedAccess: %v", err)
	}

	_, err := v.VerifyRequest(peerRequest(token, nil))
	requireReason(t, err, "sender_proof_required", "no TLS state")
	_, err = v.VerifyRequest(peerRequest(token, other))
	requireReason(t, err, "sender_proof_required", "another leaf")

	spoofed := peerRequest(token, nil)
	spoofed.Header.Set("X-Client-Cert", base64.StdEncoding.EncodeToString(leaf.Raw))
	spoofed.Header.Set("X-Forwarded-Client-Cert", "Cert="+base64.StdEncoding.EncodeToString(leaf.Raw))
	_, err = v.VerifyRequest(spoofed)
	requireReason(t, err, "sender_proof_required", "spoofed certificate header")

	cl, err := v.VerifyRequest(peerRequest(token, leaf))
	if err != nil {
		t.Fatalf("matching peer: %v", err)
	}
	if cl.ConfirmationCertificateSHA256 == nil || *cl.ConfirmationCertificateSHA256 != sum {
		t.Fatalf("claims binding = %v", cl.ConfirmationCertificateSHA256)
	}
	principal, ok := cl.DelegatedAccess()
	if !ok || principal.ConfirmationCertificateSHA256 == nil || *principal.ConfirmationCertificateSHA256 != sum {
		t.Fatalf("principal = %+v, %v", principal, ok)
	}
	if _, _, err := v.VerifyDelegatedAccessRequest(peerRequest(token, leaf)); err != nil {
		t.Fatalf("VerifyDelegatedAccessRequest: %v", err)
	}
	if _, _, err := v.VerifyDelegatedAccessRequest(peerRequest(token, other)); !errors.Is(err, ErrSenderProofRequired) {
		t.Fatalf("VerifyDelegatedAccessRequest another leaf: %v", err)
	}

	rec := httptest.NewRecorder()
	Required(v)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) })).ServeHTTP(rec, peerRequest(token, nil))
	if rec.Code != http.StatusUnauthorized || !strings.Contains(rec.Body.String(), "sender_proof_required") {
		t.Fatalf("Required without peer: %d %s", rec.Code, rec.Body.String())
	}
}

func TestUnboundDelegatedTokenIgnoresPeer(t *testing.T) {
	v, signer := confirmationVerifier(t)
	token := signTyped(t, signer, DelegatedAccessTokenType, delegatedClaims(nil))
	if _, err := v.Verify(token); err != nil {
		t.Fatalf("Verify: %v", err)
	}
	for name, peer := range map[string]*x509.Certificate{"no peer": nil, "any peer": confirmationLeaf(t)} {
		cl, err := v.VerifyRequest(peerRequest(token, peer))
		if err != nil || cl.ConfirmationCertificateSHA256 != nil {
			t.Fatalf("%s: %v, binding %v", name, err, cl.ConfirmationCertificateSHA256)
		}
	}
}

func TestConfirmationClaimShapeIsStrict(t *testing.T) {
	v, signer := confirmationVerifier(t)
	leaf := confirmationLeaf(t)
	good := jwtkit.CertificateThumbprintSHA256(leaf.Raw)

	if _, err := v.VerifyRequest(peerRequest(signDelegatedPayload(t, signer, `"cnf":{"x5t#S256":"`+good+`"}`), leaf)); err != nil {
		t.Fatalf("exact shape: %v", err)
	}
	rejected := map[string]string{
		"string":           `"cnf":"` + good + `"`,
		"empty object":     `"cnf":{}`,
		"null":             `"cnf":null`,
		"array":            `"cnf":["` + good + `"]`,
		"number member":    `"cnf":{"x5t#S256":1}`,
		"null member":      `"cnf":{"x5t#S256":null}`,
		"short":            `"cnf":{"x5t#S256":"abc"}`,
		"padded":           `"cnf":{"x5t#S256":"` + good + `="}`,
		"not base64url":    `"cnf":{"x5t#S256":"` + strings.Repeat("+", 43) + `"}`,
		"extra member":     `"cnf":{"x5t#S256":"` + good + `","jwk":{}}`,
		"other method":     `"cnf":{"jkt":"` + good + `"}`,
		"duplicate cnf":    `"cnf":{"x5t#S256":"` + good + `"},"cnf":{"x5t#S256":"` + good + `"}`,
		"duplicate member": `"cnf":{"x5t#S256":"` + good + `","x5t#S256":"` + good + `"}`,
	}
	for name, cnf := range rejected {
		_, err := v.VerifyRequest(peerRequest(signDelegatedPayload(t, signer, cnf), leaf))
		requireReason(t, err, "invalid_confirmation", name)
	}
}

func TestConfirmationOnNonDelegatedTokenRejected(t *testing.T) {
	v, signer := confirmationVerifier(t)
	leaf := confirmationLeaf(t)
	cnf := jwtkit.ConfirmationClaimValue(jwtkit.CertificateSHA256(leaf.Raw))
	now := time.Now()
	base := jwt.MapClaims{"iss": confirmationIssuer, "aud": []string{"resource"}, "iat": now.Unix(), "exp": now.Add(time.Minute).Unix(), "cnf": cnf}

	access := jwt.MapClaims{"sub": "local-user"}
	for k, val := range base {
		access[k] = val
	}
	_, err := v.VerifyRequest(peerRequest(signTyped(t, signer, AccessTokenType, access), leaf))
	requireReason(t, err, "confirmation_wrong_token_type", "access token")

	_, err = v.VerifyRequest(peerRequest(signTyped(t, signer, RemoteApplicationAccessTokenType, base), leaf))
	requireReason(t, err, "confirmation_wrong_token_type", "remote application token")
}

func TestCertificateBoundExpiredTokenRejected(t *testing.T) {
	v, signer := confirmationVerifier(t)
	leaf := confirmationLeaf(t)
	token := signTyped(t, signer, DelegatedAccessTokenType, delegatedClaims(map[string]any{
		"cnf": jwtkit.ConfirmationClaimValue(jwtkit.CertificateSHA256(leaf.Raw)),
		"exp": time.Now().Add(-5 * time.Minute).Unix(),
	}))
	_, err := v.VerifyRequest(peerRequest(token, leaf))
	requireReason(t, err, "token_expired", "expired bound token with matching peer")
}
