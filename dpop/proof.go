// Package dpop verifies the ES256/P-256 profile of RFC 9449 sender proofs.
// Proofs establish possession of a key, never user identity or authorization.
package dpop

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	jwt "github.com/golang-jwt/jwt/v5"
)

var (
	ErrInvalidProof      = errors.New("invalid DPoP proof")
	ErrReplay            = errors.New("DPoP proof already used")
	ErrReplayUnavailable = errors.New("DPoP replay protection unavailable")
)

// ReplayGuard atomically claims key until ttl elapses. It returns true only
// for the first claim. All receiver replicas must share the same store. Errors
// must fail closed; implementations must not evict live claims to admit others.
// Keys are fixed-size SHA-256 digests; ttl is at most 121 seconds.
type ReplayGuard func(ctx context.Context, key string, ttl time.Duration) (bool, error)

// VerifyRequest verifies exactly one DPoP header against a trusted public URL,
// the request method and the presented access token. expected is the access
// token's cnf.jkt; nil is allowed only when binding a newly issued token to the
// proof's key. AuthKit requires ath even on authenticated delegation mints.
// Call only after authenticating the access token. requestURL must come from
// server configuration or trusted routing, never unvalidated forwarding headers.
func VerifyRequest(r *http.Request, requestURL, accessToken string, expected *[32]byte, replay ReplayGuard) ([32]byte, error) {
	var zero [32]byte
	if r == nil || accessToken == "" || len(accessToken) > 32<<10 || len(r.Header.Values("DPoP")) != 1 {
		return zero, ErrInvalidProof
	}
	proof := r.Header.Get("DPoP")
	if len(proof) == 0 || len(proof) > 4<<10 {
		return zero, ErrInvalidProof
	}
	parts := strings.Split(proof, ".")
	if len(parts) != 3 {
		return zero, ErrInvalidProof
	}
	header, err := decodeObject(parts[0])
	if err != nil || len(header) != 3 || stringValue(header["typ"]) != "dpop+jwt" || stringValue(header["alg"]) != "ES256" {
		return zero, ErrInvalidProof
	}
	jwk, err := object(header["jwk"])
	if err != nil || len(jwk) != 4 || stringValue(jwk["kty"]) != "EC" || stringValue(jwk["crv"]) != "P-256" {
		return zero, ErrInvalidProof
	}
	x, y := stringValue(jwk["x"]), stringValue(jwk["y"])
	xb, xe := base64.RawURLEncoding.Strict().DecodeString(x)
	yb, ye := base64.RawURLEncoding.Strict().DecodeString(y)
	if xe != nil || ye != nil || len(xb) != 32 || len(yb) != 32 {
		return zero, ErrInvalidProof
	}
	key := &ecdsa.PublicKey{Curve: elliptic.P256(), X: new(big.Int).SetBytes(xb), Y: new(big.Int).SetBytes(yb)}
	if !key.Curve.IsOnCurve(key.X, key.Y) {
		return zero, ErrInvalidProof
	}
	signature, err := base64.RawURLEncoding.Strict().DecodeString(parts[2])
	if err != nil || jwt.SigningMethodES256.Verify(parts[0]+"."+parts[1], signature, key) != nil {
		return zero, ErrInvalidProof
	}
	claims, err := decodeObject(parts[1])
	if err != nil {
		return zero, ErrInvalidProof
	}
	jti := stringValue(claims["jti"])
	if len(jti) < 16 || len(jti) > 128 || strings.ContainsAny(jti, " \t\r\n") || stringValue(claims["htm"]) != r.Method {
		return zero, ErrInvalidProof
	}
	proofURL := stringValue(claims["htu"])
	parsed, err := url.Parse(proofURL)
	if err != nil || parsed.RawQuery != "" || parsed.ForceQuery || parsed.Fragment != "" || strings.Contains(proofURL, "#") {
		return zero, ErrInvalidProof
	}
	wantURL, err := canonicalURL(requestURL)
	if err != nil {
		return zero, ErrInvalidProof
	}
	gotURL, err := canonicalURL(proofURL)
	if err != nil || gotURL != wantURL {
		return zero, ErrInvalidProof
	}
	var iat int64
	if err := json.Unmarshal(claims["iat"], &iat); err != nil {
		return zero, ErrInvalidProof
	}
	now := time.Now()
	if iat < now.Unix()-60 || iat > now.Unix()+60 {
		return zero, ErrInvalidProof
	}
	ath := sha256.Sum256([]byte(accessToken))
	if stringValue(claims["ath"]) != base64.RawURLEncoding.EncodeToString(ath[:]) {
		return zero, ErrInvalidProof
	}
	// RFC 7638: lexicographic member order and only required public members.
	canonicalKey := `{"crv":"P-256","kty":"EC","x":"` + x + `","y":"` + y + `"}`
	thumbprint := sha256.Sum256([]byte(canonicalKey))
	if expected != nil && *expected != thumbprint {
		return zero, ErrInvalidProof
	}
	if replay == nil {
		return zero, ErrReplayUnavailable
	}
	replayKey := sha256.Sum256(append(thumbprint[:], []byte(jti)...))
	ttl := time.Unix(iat+61, 0).Sub(now)
	claimed, err := replay(r.Context(), base64.RawURLEncoding.EncodeToString(replayKey[:]), ttl)
	if err != nil {
		return zero, fmt.Errorf("%w: %w", ErrReplayUnavailable, err)
	}
	if !claimed {
		return zero, ErrReplay
	}
	return thumbprint, nil
}

func decodeObject(encoded string) (map[string]json.RawMessage, error) {
	raw, err := base64.RawURLEncoding.Strict().DecodeString(encoded)
	if err != nil {
		return nil, err
	}
	return object(raw)
}

// object rejects duplicate members, non-objects and trailing JSON.
func object(raw []byte) (map[string]json.RawMessage, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	tok, err := dec.Token()
	if err != nil || tok != json.Delim('{') {
		return nil, ErrInvalidProof
	}
	out := map[string]json.RawMessage{}
	for dec.More() {
		tok, err := dec.Token()
		if err != nil {
			return nil, err
		}
		key, ok := tok.(string)
		if !ok {
			return nil, ErrInvalidProof
		}
		if _, dup := out[key]; dup {
			return nil, ErrInvalidProof
		}
		var value json.RawMessage
		if err := dec.Decode(&value); err != nil {
			return nil, err
		}
		out[key] = value
	}
	if _, err := dec.Token(); err != nil {
		return nil, err
	}
	if err := dec.Decode(new(any)); err != io.EOF {
		return nil, ErrInvalidProof
	}
	return out, nil
}

func stringValue(raw json.RawMessage) string {
	var value string
	_ = json.Unmarshal(raw, &value)
	return value
}

func canonicalURL(raw string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil || u.User != nil || u.Host == "" || u.Opaque != "" {
		return "", ErrInvalidProof
	}
	u.Scheme, u.Host = strings.ToLower(u.Scheme), strings.ToLower(u.Host)
	if u.Scheme != "https" {
		ip := net.ParseIP(u.Hostname())
		if u.Scheme != "http" || (u.Hostname() != "localhost" && (ip == nil || !ip.IsLoopback())) {
			return "", ErrInvalidProof
		}
	}
	if (u.Scheme == "https" && u.Port() == "443") || (u.Scheme == "http" && u.Port() == "80") {
		u.Host = u.Hostname()
		if strings.Contains(u.Host, ":") {
			u.Host = "[" + u.Host + "]"
		}
	}
	path := u.EscapedPath()
	if path == "" {
		path = "/"
	}
	return u.Scheme + "://" + u.Host + path, nil
}
