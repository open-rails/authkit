package jose

import (
	"crypto"
	"errors"
	"fmt"
	"strings"

	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/keys"
)

// StaticKeys is a static key list by kid, under AuthKit's key policy: the
// one rule for registering a list and for verifying with it. Every key has a
// distinct kid, its KID or else its JWK's, without surrounding whitespace. A
// token naming no kid still selects a list's only key (jwks.Select).
func StaticKeys(set []iam.RemoteApplicationKey) (map[string]crypto.PublicKey, error) {
	out := make(map[string]crypto.PublicKey, len(set))
	for i, k := range set {
		kid, pub, err := staticKey(k)
		switch {
		case err != nil:
			return nil, fmt.Errorf("key %d: %w", i, err)
		case kid == "":
			return nil, fmt.Errorf("key %d: kid required (a PEM key has none of its own)", i)
		case kid != strings.TrimSpace(kid):
			return nil, fmt.Errorf("key %d: kid %q has surrounding whitespace", i, kid)
		}
		if _, dup := out[kid]; dup {
			return nil, fmt.Errorf("key %d: duplicate kid %q", i, kid)
		}
		out[kid] = pub
	}
	return out, nil
}

func staticKey(k iam.RemoteApplicationKey) (string, crypto.PublicKey, error) {
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
