package jwtkit

import (
	"crypto"
	"strings"
)

// KeyRing is a KeySource that exposes one active signer and a merged set of
// verification public keys (active + retired).
type KeyRing struct {
	active Signer
	pubs   map[string]crypto.PublicKey
}

// NewKeyRing builds a KeyRing. verificationKeys are merged with the active
// signer's public key (when the signer implements PublicKeySigner). Retired keys
// remain in JWKS for rotation without being used to sign.
func NewKeyRing(active Signer, verificationKeys map[string]crypto.PublicKey) *KeyRing {
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
	return &KeyRing{active: active, pubs: pubs}
}

func (k *KeyRing) ActiveSigner() Signer { return k.active }

func (k *KeyRing) PublicKeys() map[string]crypto.PublicKey {
	return clonePublicKeyMap(k.pubs)
}
