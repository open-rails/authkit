// Package jose is AuthKit's JWT mechanics: signing with a keys.Signer,
// signature verification, the token types, claim readers, sender-binding
// (cnf) claims and JWKS serving. golang-jwt stays behind it, out of the public
// API. It holds no policy: which issuers, audiences and token profiles are
// trusted is verify's and the engine's.
package jose

import (
	"bytes"
	"context"
	"crypto"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"

	jwt "github.com/golang-jwt/jwt/v5"
	"github.com/open-rails/authkit/keys"
)

// JOSE typ header values: each AuthKit token class has its own.
const (
	AccessTokenType          = "access+jwt"
	DelegatedAccessTokenType = "delegated-access+jwt"
	// RemoteApplicationAccessTokenType is a remote application acting as
	// itself: no sub, no delegated_sub; its identity is the validated iss.
	RemoteApplicationAccessTokenType = "remote-application-access+jwt"
	ServiceJWTType                   = "service+jwt"
)

// Algorithms are the JWS algorithms AuthKit verifies: asymmetric only, so
// "none" and HS* never pass.
var Algorithms = []string{"RS256", "ES256", "ES384", "ES512", "EdDSA"}

var b64 = base64.RawURLEncoding

// Sign signs claims as a compact JWS with signer; typ, when set, becomes the
// header's typ.
func Sign(ctx context.Context, signer keys.Signer, typ string, claims map[string]any) (string, error) {
	if signer == nil {
		return "", errors.New("signer required")
	}
	kid := signer.KID()
	if kid == "" || kid != strings.TrimSpace(kid) {
		return "", errors.New("signer kid required")
	}
	header := map[string]any{"alg": signer.Algorithm(), "kid": kid}
	if typ != "" {
		header["typ"] = typ
	}
	h, err := json.Marshal(header)
	if err != nil {
		return "", err
	}
	c, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	input := b64.EncodeToString(h) + "." + b64.EncodeToString(c)
	sig, err := signer.Sign(ctx, []byte(input))
	if err != nil {
		return "", err
	}
	return input + "." + b64.EncodeToString(sig), nil
}

// ErrSignature is a signature that does not verify under the key it names.
var ErrSignature = errors.New("jose: invalid signature")

// KeyFunc returns the key a token's signature must verify under, from its
// header alg and kid and its unverified claims.
type KeyFunc func(alg, kid string, claims map[string]any) (crypto.PublicKey, error)

// Verify checks token's signature with the key keyFor returns, for an alg in
// Algorithms. It returns the header typ and the claims; on error the claims
// are set when the token parsed, only for choosing an error to report. A
// signature failure is ErrSignature; keyFor's error is returned wrapped.
func Verify(token string, keyFor KeyFunc) (typ string, claims map[string]any, err error) {
	mc := jwt.MapClaims{}
	parser := jwt.NewParser(jwt.WithoutClaimsValidation(), jwt.WithValidMethods(Algorithms))
	tok, err := parser.ParseWithClaims(token, mc, func(t *jwt.Token) (any, error) {
		alg, _ := t.Header["alg"].(string)
		kid, _ := t.Header["kid"].(string)
		return keyFor(alg, kid, mc)
	})
	switch {
	case errors.Is(err, jwt.ErrTokenSignatureInvalid):
		return "", mc, ErrSignature
	case err != nil:
		return "", mc, err
	case tok == nil || !tok.Valid:
		return "", mc, ErrSignature
	}
	typ, _ = tok.Header["typ"].(string)
	return typ, mc, nil
}

// Unverified decodes token's header typ and claims WITHOUT checking the
// signature: only to route a token to the key that will verify it, or to read
// the typ of a token whose signature was already verified.
func Unverified(token string) (typ string, claims map[string]any, ok bool) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return "", nil, false
	}
	var header struct {
		Typ string `json:"typ"`
	}
	h, err := b64.DecodeString(parts[0])
	if err != nil || json.Unmarshal(h, &header) != nil {
		return "", nil, false
	}
	p, err := b64.DecodeString(parts[1])
	if err != nil || json.Unmarshal(p, &claims) != nil {
		return "", nil, false
	}
	return header.Typ, claims, true
}

// String is the string claim key, or "".
func String(claims map[string]any, key string) string {
	s, _ := claims[key].(string)
	return s
}

// Strings is the string-array claim key; non-string elements are skipped. It
// is nil when the claim is absent and non-nil when present, even if empty.
func Strings(claims map[string]any, key string) []string {
	switch rs := claims[key].(type) {
	case []any:
		out := make([]string, 0, len(rs))
		for _, v := range rs {
			if s, ok := v.(string); ok {
				out = append(out, s)
			}
		}
		return out
	case []string:
		return rs
	}
	return nil
}

// Time is the NumericDate claim key.
func Time(claims map[string]any, key string) (time.Time, bool) {
	switch t := claims[key].(type) {
	case float64:
		return time.Unix(int64(t), 0), true
	case int64:
		return time.Unix(t, 0), true
	case json.Number:
		i, err := t.Int64()
		return time.Unix(i, 0), err == nil
	}
	return time.Time{}, false
}

// Audiences is the aud claim as a list, blanks dropped.
func Audiences(claims map[string]any) []string {
	var raw []string
	switch a := claims["aud"].(type) {
	case string:
		raw = []string{a}
	case []any:
		for _, item := range a {
			if s, ok := item.(string); ok {
				raw = append(raw, s)
			}
		}
	case []string:
		raw = a
	}
	out := make([]string, 0, len(raw))
	for _, s := range raw {
		if s = strings.TrimSpace(s); s != "" {
			out = append(out, s)
		}
	}
	return out
}

// Object is the object-valued claim key with each member kept as raw JSON,
// nil when absent, empty or not an object.
func Object(claims map[string]any, key string) map[string]json.RawMessage {
	obj, ok := claims[key].(map[string]any)
	if !ok || len(obj) == 0 {
		return nil
	}
	out := make(map[string]json.RawMessage, len(obj))
	for k, val := range obj {
		if b, err := json.Marshal(val); err == nil {
			out[k] = b
		}
	}
	return out
}

// RawClaim reads one top-level claim off the payload strictly: a duplicate
// key, which a decoded map would silently collapse, is an error.
func RawClaim(token, key string) (raw json.RawMessage, present bool, err error) {
	errMalformed := errors.New("malformed token payload")
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, false, errMalformed
	}
	payload, err := b64.DecodeString(parts[1])
	if err != nil {
		return nil, false, errMalformed
	}
	dec := json.NewDecoder(bytes.NewReader(payload))
	if tok, err := dec.Token(); err != nil || tok != json.Delim('{') {
		return nil, false, errMalformed
	}
	for dec.More() {
		name, err := dec.Token()
		if err != nil {
			return nil, false, errMalformed
		}
		var value json.RawMessage
		if err := dec.Decode(&value); err != nil {
			return nil, false, errMalformed
		}
		if name == key {
			if present {
				return nil, true, errMalformed
			}
			present, raw = true, value
		}
	}
	if tok, err := dec.Token(); err != nil || tok != json.Delim('}') {
		return nil, false, errMalformed
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, false, errMalformed
	}
	return raw, present, nil
}

// RequestToken is the request's one Authorization credential and whether it
// uses the DPoP scheme; "" unless the header is exactly "Bearer <token>" or
// "DPoP <token>".
func RequestToken(r *http.Request) (token string, dpop bool) {
	if r == nil || len(r.Header.Values("Authorization")) != 1 {
		return "", false
	}
	scheme, token, ok := strings.Cut(r.Header.Get("Authorization"), " ")
	dpop = strings.EqualFold(scheme, "DPoP")
	if !ok || !dpop && !strings.EqualFold(scheme, "Bearer") || token == "" || strings.ContainsAny(token, " \t\r\n") {
		return "", dpop
	}
	return token, dpop
}
