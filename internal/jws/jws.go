// Package jws parses compact JWS strictly, for the JWTs clients sign with
// their own keys (DPoP proofs, jwt-bearer assertions, device-key
// capabilities): duplicate members, non-objects and trailing JSON are
// refused, and only the algorithm each caller names verifies.
package jws

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"strings"

	jwt "github.com/golang-jwt/jwt/v5"
)

// ErrInvalid is any malformed or unverified JWS.
var ErrInvalid = errors.New("invalid JWS")

// Parsed is a compact JWS split and decoded, not yet verified.
type Parsed struct {
	Header, Claims map[string]json.RawMessage
	signingInput   string
	signature      []byte
}

// Parse splits and decodes compact; nothing is verified.
func Parse(compact string) (Parsed, error) {
	parts := strings.Split(compact, ".")
	if compact == "" || len(parts) != 3 {
		return Parsed{}, ErrInvalid
	}
	header, err := decodeObject(parts[0])
	if err != nil {
		return Parsed{}, ErrInvalid
	}
	claims, err := decodeObject(parts[1])
	if err != nil {
		return Parsed{}, ErrInvalid
	}
	signature, err := base64.RawURLEncoding.Strict().DecodeString(parts[2])
	if err != nil {
		return Parsed{}, ErrInvalid
	}
	return Parsed{Header: header, Claims: claims, signingInput: parts[0] + "." + parts[1], signature: signature}, nil
}

// VerifyEmbeddedES256 verifies an ES256 signature by the public P-256 key
// the header carries (jwk: exactly kty, crv, x and y), and returns the key's
// RFC 7638 thumbprint (unpadded base64url). It proves possession of that
// key, nothing else.
func (p Parsed) VerifyEmbeddedES256() (string, error) {
	if String(p.Header["alg"]) != "ES256" {
		return "", ErrInvalid
	}
	jwk, err := Object(p.Header["jwk"])
	if err != nil || len(jwk) != 4 || String(jwk["kty"]) != "EC" || String(jwk["crv"]) != "P-256" {
		return "", ErrInvalid
	}
	x, y := String(jwk["x"]), String(jwk["y"])
	xb, xe := base64.RawURLEncoding.Strict().DecodeString(x)
	yb, ye := base64.RawURLEncoding.Strict().DecodeString(y)
	if xe != nil || ye != nil || len(xb) != 32 || len(yb) != 32 {
		return "", ErrInvalid
	}
	key, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), append(append([]byte{4}, xb...), yb...))
	if err != nil || jwt.SigningMethodES256.Verify(p.signingInput, p.signature, key) != nil {
		return "", ErrInvalid
	}
	// RFC 7638: lexicographic member order and only required public members.
	sum := sha256.Sum256([]byte(`{"crv":"P-256","kty":"EC","x":"` + x + `","y":"` + y + `"}`))
	return base64.RawURLEncoding.EncodeToString(sum[:]), nil
}

// VerifyEdDSA verifies an EdDSA (Ed25519) signature by key.
func (p Parsed) VerifyEdDSA(key ed25519.PublicKey) error {
	if String(p.Header["alg"]) != "EdDSA" || len(key) != ed25519.PublicKeySize || !ed25519.Verify(key, []byte(p.signingInput), p.signature) {
		return ErrInvalid
	}
	return nil
}

func decodeObject(encoded string) (map[string]json.RawMessage, error) {
	raw, err := base64.RawURLEncoding.Strict().DecodeString(encoded)
	if err != nil {
		return nil, err
	}
	return Object(raw)
}

// Object decodes one JSON object, refusing duplicate members, any other
// value and trailing JSON.
func Object(raw []byte) (map[string]json.RawMessage, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	tok, err := dec.Token()
	if err != nil || tok != json.Delim('{') {
		return nil, ErrInvalid
	}
	out := map[string]json.RawMessage{}
	for dec.More() {
		tok, err := dec.Token()
		if err != nil {
			return nil, err
		}
		key, ok := tok.(string)
		if !ok {
			return nil, ErrInvalid
		}
		if _, dup := out[key]; dup {
			return nil, ErrInvalid
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
		return nil, ErrInvalid
	}
	return out, nil
}

// String is raw's string value; "" for anything else.
func String(raw json.RawMessage) string {
	var value string
	_ = json.Unmarshal(raw, &value)
	return value
}
