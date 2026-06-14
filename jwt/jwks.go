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

// RSAPublicToJWK converts an RSA public key to a JWK.
func RSAPublicToJWK(pub *rsa.PublicKey, kid, alg string) JWK {
	return PublicToJWK(pub, kid, alg)
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
		return &rsa.PublicKey{N: new(big.Int).SetBytes(nBytes), E: int(eInt.Int64())}, nil
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
		return &ecdsa.PublicKey{
			Curve: curve,
			X:     new(big.Int).SetBytes(xBytes),
			Y:     new(big.Int).SetBytes(yBytes),
		}, nil
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
func ServeJWKS(w http.ResponseWriter, r *http.Request, ks JWKS) {
	b, _ := json.Marshal(ks)
	sum := sha256.Sum256(b)
	etag := "\"" + hex.EncodeToString(sum[:]) + "\""

	if inm := r.Header.Get("If-None-Match"); inm != "" && inm == etag {
		w.WriteHeader(http.StatusNotModified)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "public, max-age=300, must-revalidate")
	w.Header().Set("ETag", etag)
	_, _ = w.Write(b)
}

func base64URLEncode(i *big.Int) string {
	b := i.Bytes()
	for len(b) > 0 && b[0] == 0x00 {
		b = b[1:]
	}
	return base64.RawURLEncoding.EncodeToString(b)
}
