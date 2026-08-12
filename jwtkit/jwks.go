package jwtkit

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"strings"
)

// JWK represents a JSON Web Key (RSA, EC, or OKP).
type JWK struct {
	Kty string `json:"kty"`
	Use string `json:"use,omitempty"`
	Kid string `json:"kid,omitempty"`
	Alg string `json:"alg,omitempty"`
	// RSA
	N string `json:"n,omitempty"`
	E string `json:"e,omitempty"`
	// EC / OKP
	Crv string `json:"crv,omitempty"`
	X   string `json:"x,omitempty"`
	Y   string `json:"y,omitempty"`
}

type JWKS struct {
	Keys []JWK `json:"keys"`
}

// PublicToJWK converts a supported public key to a JWK.
func PublicToJWK(pub crypto.PublicKey, kid, alg string) JWK {
	if strings.TrimSpace(alg) == "" {
		alg = AlgorithmForPublicKey(pub)
	}
	switch k := pub.(type) {
	case *rsa.PublicKey:
		return JWK{
			Kty: "RSA", Use: "sig", Kid: kid, Alg: alg,
			N: base64URLEncode(k.N),
			E: base64URLEncode(big.NewInt(int64(k.E))),
		}
	case *ecdsa.PublicKey:
		crv := k.Curve.Params().Name
		size := (k.Curve.Params().BitSize + 7) / 8
		// Go 1.26 deprecated direct big.Int X/Y access on ecdsa.PublicKey. Derive
		// the fixed-length JWK coordinates from the uncompressed SEC1 point
		// (0x04 || X || Y) via crypto/ecdh — the supported path for the NIST
		// curves (P-256/384/521) we sign with.
		var x, y string
		if ek, err := k.ECDH(); err == nil {
			if raw := ek.Bytes(); len(raw) == 1+2*size {
				x = base64.RawURLEncoding.EncodeToString(raw[1 : 1+size])
				y = base64.RawURLEncoding.EncodeToString(raw[1+size:])
			}
		}
		return JWK{Kty: "EC", Use: "sig", Kid: kid, Alg: alg, Crv: crv, X: x, Y: y}
	case ed25519.PublicKey:
		return JWK{
			Kty: "OKP", Use: "sig", Kid: kid, Alg: alg,
			Crv: "Ed25519",
			X:   base64.RawURLEncoding.EncodeToString(k),
		}
	default:
		return JWK{Kid: kid, Alg: alg}
	}
}

// JWKToPublicKey parses a single JWK into a crypto.PublicKey.
func JWKToPublicKey(j JWK) (crypto.PublicKey, error) {
	switch strings.ToUpper(strings.TrimSpace(j.Kty)) {
	case "RSA":
		if j.N == "" || j.E == "" {
			return nil, errors.New("rsa_jwk_missing_n_or_e")
		}
		nBytes, err := base64.RawURLEncoding.DecodeString(j.N)
		if err != nil {
			return nil, err
		}
		eBytes, err := base64.RawURLEncoding.DecodeString(j.E)
		if err != nil {
			return nil, err
		}
		eInt := new(big.Int).SetBytes(eBytes)
		if !eInt.IsInt64() {
			return nil, errors.New("bad_rsa_exponent")
		}
		pub := &rsa.PublicKey{N: new(big.Int).SetBytes(nBytes), E: int(eInt.Int64())}
		if err := validateRSAPublicKey(pub); err != nil {
			return nil, err
		}
		return pub, nil
	case "EC":
		curve, err := curveForCRV(j.Crv)
		if err != nil {
			return nil, err
		}
		xBytes, err := base64.RawURLEncoding.DecodeString(j.X)
		if err != nil {
			return nil, err
		}
		yBytes, err := base64.RawURLEncoding.DecodeString(j.Y)
		if err != nil {
			return nil, err
		}
		pub := &ecdsa.PublicKey{
			Curve: curve,
			X:     new(big.Int).SetBytes(xBytes),
			Y:     new(big.Int).SetBytes(yBytes),
		}
		if err := validateECPublicKey(pub); err != nil {
			return nil, err
		}
		return pub, nil
	case "OKP":
		if strings.ToUpper(strings.TrimSpace(j.Crv)) != "ED25519" {
			return nil, fmt.Errorf("%w: %s", ErrUnsupportedJWK, j.Crv)
		}
		xBytes, err := base64.RawURLEncoding.DecodeString(j.X)
		if err != nil {
			return nil, err
		}
		if len(xBytes) != ed25519.PublicKeySize {
			return nil, errors.New("bad_ed25519_jwk_x")
		}
		return ed25519.PublicKey(xBytes), nil
	default:
		return nil, fmt.Errorf("%w: %s", ErrUnsupportedJWK, j.Kty)
	}
}

var ErrUnsupportedJWK = errors.New("unsupported_jwk")

// JWKSToPublicKeys parses all supported keys in a JWKS document.
func JWKSToPublicKeys(ks JWKS) (map[string]crypto.PublicKey, error) {
	out := make(map[string]crypto.PublicKey)
	var skipped int
	for _, j := range ks.Keys {
		pub, err := JWKToPublicKey(j)
		if err != nil {
			if errors.Is(err, ErrUnsupportedJWK) {
				skipped++
				continue
			}
			return nil, err
		}
		kid := strings.TrimSpace(j.Kid)
		if kid == "" {
			kid = "default"
		}
		out[kid] = pub
	}
	if len(out) == 0 {
		if skipped > 0 {
			return nil, ErrUnsupportedJWK
		}
		return nil, errors.New("empty_jwks")
	}
	return out, nil
}

const (
	// minRSABits is the smallest RSA modulus accepted from a JWKS: the NIST /
	// RFC 7518 floor. A 1024-bit modulus is factorable by a well-resourced
	// attacker, so accepting one means accepting forged tokens.
	minRSABits = 2048
	// maxRSABits bounds the modulus so a hostile JWKS cannot make every
	// verification pathologically expensive (modexp is quadratic in the modulus).
	maxRSABits = 8192
)

// validateRSAPublicKey rejects weak or degenerate RSA keys before they reach the
// verifier. JWKToPublicKey previously accepted whatever modulus the document
// supplied, so a misconfigured — or attacker-influenced — issuer could publish a
// trivially factorable key and have tokens signed with it verify.
func validateRSAPublicKey(pub *rsa.PublicKey) error {
	if pub == nil || pub.N == nil || pub.N.Sign() <= 0 {
		return errors.New("invalid_rsa_modulus")
	}
	if bits := pub.N.BitLen(); bits < minRSABits {
		return fmt.Errorf("rsa_key_too_small: %d bits (min %d)", bits, minRSABits)
	} else if bits > maxRSABits {
		return fmt.Errorf("rsa_key_too_large: %d bits (max %d)", bits, maxRSABits)
	}
	// e = 1 is the identity map and an even exponent is never a valid RSA
	// exponent; both make "verification" meaningless rather than merely weak.
	if pub.E < 3 || pub.E%2 == 0 {
		return fmt.Errorf("invalid_rsa_exponent: %d", pub.E)
	}
	return nil
}

// validateECPublicKey confirms the (X, Y) the JWKS supplied is a real point on
// the named curve. An off-curve or identity point is the invalid-curve attack
// vector; ecdsa.PublicKey.ECDH does the on-curve check and the coordinate-range
// check for us, and is already the idiom this file uses in PublicToJWK.
func validateECPublicKey(pub *ecdsa.PublicKey) error {
	if pub == nil || pub.Curve == nil {
		return errors.New("invalid_ec_point")
	}
	if _, err := pub.ECDH(); err != nil {
		return fmt.Errorf("ec_point_not_on_curve: %w", err)
	}
	return nil
}

func curveForCRV(crv string) (elliptic.Curve, error) {
	switch strings.ToUpper(strings.TrimSpace(crv)) {
	case "P-256":
		return elliptic.P256(), nil
	case "P-384":
		return elliptic.P384(), nil
	case "P-521":
		return elliptic.P521(), nil
	default:
		return nil, fmt.Errorf("%w: %s", ErrUnsupportedJWK, crv)
	}
}

// ServeJWKS writes JWKS JSON to the ResponseWriter.
//
// A JWKS endpoint is fetched constantly by every verifier and normally sits
// behind a CDN or proxy, so the caching contract is part of the contract:
//
//   - ETag and Cache-Control are set BEFORE the conditional branch, so the 304
//     carries them too. RFC 7232 requires the validator on a 304; dropping it
//     makes an intermediary discard its entry and refetch, which is the opposite
//     of what the conditional request was for.
//   - If-None-Match is matched per RFC 7232 §3.2 — "*", a comma-separated
//     candidate list, and the weak "W/" prefix (If-None-Match uses the weak
//     comparison function). The previous exact-string compare silently disabled
//     caching for any standards-compliant client that sent one of those.
//   - X-Content-Type-Options: nosniff, so a browser cannot be steered into
//     treating the document as anything but JSON.
func ServeJWKS(w http.ResponseWriter, r *http.Request, ks JWKS) {
	b, _ := json.Marshal(ks)
	sum := sha256.Sum256(b)
	etag := "\"" + hex.EncodeToString(sum[:]) + "\""

	h := w.Header()
	h.Set("Cache-Control", "public, max-age=300, must-revalidate")
	h.Set("ETag", etag)
	h.Set("X-Content-Type-Options", "nosniff")

	if inm := r.Header.Get("If-None-Match"); inm != "" && etagMatches(inm, etag) {
		w.WriteHeader(http.StatusNotModified)
		return
	}

	h.Set("Content-Type", "application/json")
	_, _ = w.Write(b)
}

// etagMatches reports whether an If-None-Match header value matches etag, using
// the weak comparison RFC 7232 §2.3.2 specifies for If-None-Match: "*" matches
// any current representation, the value is a comma-separated list, and a "W/"
// prefix on either side is ignored.
func etagMatches(ifNoneMatch, etag string) bool {
	ifNoneMatch = strings.TrimSpace(ifNoneMatch)
	if ifNoneMatch == "*" {
		return true
	}
	etag = strings.TrimPrefix(etag, "W/")
	for candidate := range strings.SplitSeq(ifNoneMatch, ",") {
		if strings.TrimPrefix(strings.TrimSpace(candidate), "W/") == etag {
			return true
		}
	}
	return false
}

func base64URLEncode(i *big.Int) string {
	b := i.Bytes()
	for len(b) > 0 && b[0] == 0x00 {
		b = b[1:]
	}
	return base64.RawURLEncoding.EncodeToString(b)
}
