package jwtkit

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
)

// PublicKeySigner is implemented by in-memory signers that expose their public key.
type PublicKeySigner interface {
	Signer
	PublicKey() crypto.PublicKey
}

// ParsePublicKeyFromPEM parses a PKIX/SPKI, certificate, or PKCS#1 RSA public key PEM.
func ParsePublicKeyFromPEM(pemText string) (crypto.PublicKey, error) {
	return ParsePublicKeyFromPEMBytes([]byte(pemText))
}

// ParsePublicKeyFromPEMBytes parses a supported public key PEM block.
func ParsePublicKeyFromPEMBytes(pemBytes []byte) (crypto.PublicKey, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, errors.New("bad_pem")
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		if cert, err2 := x509.ParseCertificate(block.Bytes); err2 == nil {
			return cert.PublicKey, nil
		}
		if rsaPub, err3 := x509.ParsePKCS1PublicKey(block.Bytes); err3 == nil {
			return rsaPub, nil
		}
		return nil, err
	}
	switch pub.(type) {
	case *rsa.PublicKey, *ecdsa.PublicKey, ed25519.PublicKey:
		return pub, nil
	default:
		return nil, fmt.Errorf("unsupported public key type %T", pub)
	}
}

// NewSignerFromPEM constructs a Signer from a PEM-encoded private key (RSA, EC, or Ed25519).
func NewSignerFromPEM(kid string, pemBytes []byte) (Signer, error) {
	if len(pemBytes) == 0 {
		return nil, errors.New("empty private key pem")
	}
	blk, _ := pem.Decode(pemBytes)
	if blk == nil {
		return nil, errors.New("failed to decode private key pem")
	}
	switch blk.Type {
	case "RSA PRIVATE KEY":
		key, err := x509.ParsePKCS1PrivateKey(blk.Bytes)
		if err != nil {
			return nil, err
		}
		return &RSASigner{key: key, kid: kid}, nil
	case "EC PRIVATE KEY":
		key, err := x509.ParseECPrivateKey(blk.Bytes)
		if err != nil {
			return nil, err
		}
		return newECDSASigner(kid, key)
	default:
		key, err := x509.ParsePKCS8PrivateKey(blk.Bytes)
		if err != nil {
			return nil, err
		}
		switch k := key.(type) {
		case *rsa.PrivateKey:
			return &RSASigner{key: k, kid: kid}, nil
		case *ecdsa.PrivateKey:
			return newECDSASigner(kid, k)
		case ed25519.PrivateKey:
			return &Ed25519Signer{key: k, kid: kid}, nil
		default:
			return nil, fmt.Errorf("unsupported pkcs8 private key type %T", key)
		}
	}
}

// AlgorithmForPublicKey returns a default JWS alg for a public key when none is specified.
func AlgorithmForPublicKey(pub crypto.PublicKey) string {
	switch k := pub.(type) {
	case *rsa.PublicKey:
		return "RS256"
	case *ecdsa.PublicKey:
		switch k.Params().Name {
		case "P-384":
			return "ES384"
		case "P-521":
			return "ES512"
		default:
			return "ES256"
		}
	case ed25519.PublicKey:
		return "EdDSA"
	default:
		return ""
	}
}

func clonePublicKeyMap(in map[string]crypto.PublicKey) map[string]crypto.PublicKey {
	if in == nil {
		return nil
	}
	out := make(map[string]crypto.PublicKey, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}
