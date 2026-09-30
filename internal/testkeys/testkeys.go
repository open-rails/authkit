// Package testkeys generates signing keys for tests. Every helper panics on
// failure.
package testkeys

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"

	"github.com/open-rails/authkit/keys"
)

// RSA is a fresh RS256 signer.
func RSA(kid string) keys.Signer { return must(rsa.GenerateKey(rand.Reader, 2048))(kid) }

// EC is a fresh ES256 signer.
func EC(kid string) keys.Signer { return must(ecdsa.GenerateKey(elliptic.P256(), rand.Reader))(kid) }

// Ed25519 is a fresh EdDSA signer.
func Ed25519(kid string) keys.Signer {
	_, key, err := ed25519.GenerateKey(rand.Reader)
	return must(key, err)(kid)
}

// Source is a key source whose only key is s.
func Source(s keys.Signer) keys.Static {
	return keys.Static{Active: s, Pubs: map[string]crypto.PublicKey{s.KID(): s.Public()}}
}

func must[K crypto.Signer](key K, err error) func(kid string) keys.Signer {
	if err != nil {
		panic(err)
	}
	return func(kid string) keys.Signer {
		s, err := keys.SignerFromKey(kid, key)
		if err != nil {
			panic(err)
		}
		return s
	}
}
