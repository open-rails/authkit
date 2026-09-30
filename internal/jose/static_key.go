package jose

import (
	"crypto"
	"errors"
	"fmt"

	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/keys"
)

// StaticKey is k's kid and public key, from exactly one of its PEM and JWK,
// under AuthKit's key policy. An empty KID takes the JWK's kid.
func StaticKey(k iam.RemoteApplicationKey) (string, crypto.PublicKey, error) {
	switch {
	case (k.PublicKeyPEM == "") == (k.JWK == nil):
		return k.KID, nil, errors.New("want exactly one of public_key_pem and jwk")
	case k.JWK == nil:
		pub, err := keys.ParsePublicPEM([]byte(k.PublicKeyPEM))
		return k.KID, pub, err
	case k.KID != "" && k.JWK.Kid != "" && k.KID != k.JWK.Kid:
		return k.KID, nil, fmt.Errorf("kid disagrees with the JWK's %q", k.JWK.Kid)
	}
	kid := k.KID
	if kid == "" {
		kid = k.JWK.Kid
	}
	pub, err := keys.ParsePublicJWK(*k.JWK)
	return kid, pub, err
}
