package critical_test

import (
	"crypto/ed25519"
	"encoding/base64"
	"net/http"
	"testing"

	"github.com/mr-tron/base58"
	"github.com/open-rails/authkit"
	"github.com/open-rails/authkit/authtest"
	"github.com/open-rails/authkit/iam"
)

// wallet is a Solana wallet: an Ed25519 key and its base58 address.
type wallet struct {
	address string
	key     ed25519.PrivateKey
}

func newWallet(t *testing.T) wallet {
	t.Helper()
	pub, key, err := ed25519.GenerateKey(nil)
	noError(t, err)
	return wallet{address: base58.Encode(pub), key: key}
}

// TestCriticalSolanaSignIn signs in with a wallet as the Wallet Standard's
// signIn does: the server's message, signed by the wallet's key.
func TestCriticalSolanaSignIn(t *testing.T) {
	f := newFixture(t, authtest.WithConfig(func(c *authkit.Config) { c.SolanaNetwork = iam.SolanaMainnet }))
	challenge := func(t *testing.T, w wallet) string {
		t.Helper()
		r := f.call(t, "POST", "/solana/challenge", "", map[string]string{"address": w.address})
		r.want(t, http.StatusOK, "")
		var out struct {
			Message string `json:"message"`
		}
		decode(t, r.body, &out)
		if out.Message == "" {
			t.Fatalf("challenge answered %s", r.body)
		}
		return out.Message
	}
	// login presents message and signature as w's sign-in output.
	login := func(t *testing.T, w wallet, message string, signature []byte) response {
		t.Helper()
		return f.call(t, "POST", "/solana/login", "", map[string]any{"output": map[string]any{
			"account":       map[string]string{"address": w.address, "publicKey": base64.StdEncoding.EncodeToString(w.key.Public().(ed25519.PublicKey))},
			"signature":     base64.StdEncoding.EncodeToString(signature),
			"signedMessage": base64.StdEncoding.EncodeToString([]byte(message)),
		}})
	}
	signedIn := func(t *testing.T, r response) string {
		t.Helper()
		r.want(t, http.StatusOK, "")
		var result signInResult
		decode(t, r.body, &result)
		if result.Status != "complete" || result.Tokens == nil || result.User == nil || result.User.ID == "" {
			t.Fatalf("wallet sign-in answered %s", r.body)
		}
		f.call(t, "PATCH", "/me", result.Tokens.AccessToken, map[string]string{"preferred_language": "en"}).want(t, http.StatusOK, "")
		return result.User.ID
	}

	t.Run("AK-J46-C01_a_wallet_signs_in_by_signing_the_server's_message", func(t *testing.T) {
		w := newWallet(t)
		message := challenge(t, w)
		first := signedIn(t, login(t, w, message, ed25519.Sign(w.key, []byte(message))))
		message = challenge(t, w)
		if again := signedIn(t, login(t, w, message, ed25519.Sign(w.key, []byte(message)))); again != first {
			t.Fatalf("one wallet signed in as %s, then %s", first, again)
		}
	})

	t.Run("AK-J46-C02_another_key's_signature_and_a_replayed_message_are_refused", func(t *testing.T) {
		w, stranger := newWallet(t), newWallet(t)
		message := challenge(t, w)
		login(t, w, message, ed25519.Sign(stranger.key, []byte(message))).want(t, http.StatusUnauthorized, "invalid_signature")
		// The refused attempt spent its challenge.
		login(t, w, message, ed25519.Sign(w.key, []byte(message))).want(t, http.StatusUnauthorized, "challenge_not_found")
		message = challenge(t, w)
		tampered := ed25519.Sign(w.key, []byte(message))
		tampered[0] ^= 1
		login(t, w, message, tampered).want(t, http.StatusUnauthorized, "invalid_signature")
		message = challenge(t, w)
		signature := ed25519.Sign(w.key, []byte(message))
		signedIn(t, login(t, w, message, signature))
		login(t, w, message, signature).want(t, http.StatusUnauthorized, "challenge_not_found")
	})
}
