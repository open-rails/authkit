package jwtkit

import (
	"crypto"
	"strings"
)

// keyRing is a KeySource that exposes one active signer and a merged set of
// verification public keys (active + retired).
type keyRing struct {
	active Signer
	pubs   map[string]crypto.PublicKey
}

// newKeyRing builds a keyRing. verificationKeys are merged with the active
// signer's public key (when the signer implements PublicKeySigner). Retired keys
// remain in JWKS for rotation without being used to sign.
func newKeyRing(active Signer, verificationKeys map[string]crypto.PublicKey) *keyRing {
	pubs := clonePublicKeyMap(verificationKeys)
	if pubs == nil {
		pubs = map[string]crypto.PublicKey{}
	}
	if ps, ok := active.(PublicKeySigner); ok {
		kid := strings.TrimSpace(ps.KID())
		if kid != "" && ps.PublicKey() != nil {
			if pubs == nil {
				pubs = map[string]crypto.PublicKey{}
			}
			pubs[kid] = ps.PublicKey()
		}
	}
	return &keyRing{active: active, pubs: pubs}
}

func (k *keyRing) ActiveSigner() Signer { return k.active }

func (k *keyRing) PublicKeys() map[string]crypto.PublicKey {
	return clonePublicKeyMap(k.pubs)
}
