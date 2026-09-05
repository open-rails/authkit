package embedded

import (
	"crypto"
	"testing"

	"github.com/open-rails/authkit/jwtkit"
)

// staticTestKeys builds explicit signing keys for a test engine (no dev-key
// generation, nothing persisted under the package directory).
func staticTestKeys(t *testing.T) KeysConfig {
	t.Helper()
	s, err := jwtkit.NewRSASigner(2048, "test-kid")
	if err != nil {
		t.Fatal(err)
	}
	return KeysConfig{Source: jwtkit.StaticKeySource{Active: s, Pubs: map[string]crypto.PublicKey{s.KID(): s.PublicKey()}}}
}
