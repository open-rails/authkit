package critical_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"net/http"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/go-webauthn/webauthn/protocol/webauthncbor"
	"github.com/go-webauthn/webauthn/protocol/webauthncose"

	"github.com/open-rails/authkit"
	"github.com/open-rails/authkit/authtest"
)

const (
	passkeyRPID   = "auth.example.com"
	passkeyOrigin = "https://auth.example.com"
	merchantPage  = "https://merchant.example"
)

// TestCriticalPasskeyFrames covers passkeys inside an iframe on another
// site, as a merchant embeds the network's sign-in, with a software
// authenticator speaking WebAuthn L3's client data.
func TestCriticalPasskeyFrames(t *testing.T) {
	t.Parallel()
	t.Run("AK-J42-C01_an_admitted_page_frames_passkey_creation_and_sign_in_and_safari_needs_no_top_origin", func(t *testing.T) {
		var mu sync.Mutex
		var asked []string
		f := passkeyFixture(t, func(_ context.Context, top string) (bool, error) {
			mu.Lock()
			defer mu.Unlock()
			asked = append(asked, top)
			return top == merchantPage, nil
		})
		u := f.user(t)
		key := newSoftKey(t)
		session := f.signIn(t, u)
		key.register(t, f, session.AccessToken, ceremonyPlace{crossOrigin: true, topOrigin: merchantPage}).want(t, http.StatusCreated, "")

		tokensFrom(t, key.signIn(t, f, ceremonyPlace{crossOrigin: true, topOrigin: merchantPage}), u.ID)
		tokensFrom(t, key.signIn(t, f, ceremonyPlace{crossOrigin: true}), u.ID)
		tokensFrom(t, key.signIn(t, f, ceremonyPlace{}), u.ID)
		key.signIn(t, f, ceremonyPlace{crossOrigin: true, topOrigin: "https://evil.example"}).want(t, http.StatusUnauthorized, "invalid_credentials")
		key.signIn(t, f, ceremonyPlace{crossOrigin: true, topOrigin: "http://merchant.example"}).want(t, http.StatusUnauthorized, "invalid_credentials")

		mu.Lock()
		seen := slices.Clone(asked)
		mu.Unlock()
		if !slices.Equal(seen, []string{merchantPage, merchantPage, "https://evil.example"}) {
			t.Fatalf("PasskeyTopOrigin was asked about %v", seen)
		}

		// Safari creates in a top-level window on the RP's own origin.
		r := f.call(t, "GET", "/passkeys/window", "", nil)
		r.want(t, http.StatusOK, "")
		if !strings.HasPrefix(r.header.Get("Content-Type"), "text/html") || !strings.Contains(r.header.Get("Content-Security-Policy"), "frame-ancestors 'none'") ||
			!strings.Contains(string(r.body), "AUTHKIT_PASSKEY_OPTIONS") {
			t.Fatalf("passkey window: %s %s", r.header, r.body)
		}
		other := newSoftKey(t)
		other.register(t, f, f.signIn(t, u).AccessToken, ceremonyPlace{}).want(t, http.StatusCreated, "")
		tokensFrom(t, other.signIn(t, f, ceremonyPlace{crossOrigin: true, topOrigin: merchantPage}), u.ID)
	})

	t.Run("AK-J42-C02_without_PasskeyTopOrigin_no_passkey_ceremony_passes_in_a_cross_origin_iframe", func(t *testing.T) {
		f := passkeyFixture(t, nil)
		u := f.user(t)
		key := newSoftKey(t)
		key.register(t, f, f.signIn(t, u).AccessToken, ceremonyPlace{crossOrigin: true, topOrigin: merchantPage}).want(t, http.StatusBadRequest, "invalid_request")
		key.register(t, f, f.signIn(t, u).AccessToken, ceremonyPlace{crossOrigin: true}).want(t, http.StatusBadRequest, "invalid_request")
		key.register(t, f, f.signIn(t, u).AccessToken, ceremonyPlace{}).want(t, http.StatusCreated, "")
		key.signIn(t, f, ceremonyPlace{crossOrigin: true}).want(t, http.StatusUnauthorized, "invalid_credentials")
		key.signIn(t, f, ceremonyPlace{crossOrigin: true, topOrigin: merchantPage}).want(t, http.StatusUnauthorized, "invalid_credentials")
		tokensFrom(t, key.signIn(t, f, ceremonyPlace{}), u.ID)
	})
}

// TestCriticalPasskeys covers top-level passkey ceremonies on the relying
// party's own origin.
func TestCriticalPasskeys(t *testing.T) {
	t.Parallel()
	f := passkeyFixture(t, nil)
	u := f.user(t)
	key := newSoftKey(t)
	t.Run("AK-J42-C03_a_passkey_challenge_answers_one_ceremony", func(t *testing.T) {
		key.register(t, f, f.signIn(t, u).AccessToken, ceremonyPlace{}).want(t, http.StatusCreated, "")
		challenge := beginPasskeyLogin(t, f)
		signed := key.assert(t, challenge, ceremonyPlace{})
		tokensFrom(t, f.call(t, "POST", "/passkeys/login/finish", "", signed), u.ID)
		// The same answer again, and a fresh signature over the spent challenge.
		f.call(t, "POST", "/passkeys/login/finish", "", signed).expect(t, http.StatusUnauthorized, "invalid_credentials")
		f.call(t, "POST", "/passkeys/login/finish", "", key.assert(t, challenge, ceremonyPlace{})).expect(t, http.StatusUnauthorized, "invalid_credentials")
		// A registration's challenge never signs in.
		r := f.call(t, "POST", "/me/passkeys/register/begin", f.signIn(t, u).AccessToken, nil)
		r.want(t, http.StatusOK, "")
		var begun struct {
			PublicKey struct {
				Challenge string `json:"challenge"`
			} `json:"publicKey"`
		}
		decode(t, r.body, &begun)
		f.call(t, "POST", "/passkeys/login/finish", "", key.assert(t, begun.PublicKey.Challenge, ceremonyPlace{})).expect(t, http.StatusUnauthorized, "invalid_credentials")
		tokensFrom(t, key.signIn(t, f, ceremonyPlace{}), u.ID)
	})
	t.Run("AK-J42-C04_a_passkey_ceremony_on_another_origin_is_refused", func(t *testing.T) {
		other := newSoftKey(t)
		session := f.signIn(t, u).AccessToken
		for _, origin := range []string{"https://evil.example", "http://auth.example.com", "https://auth.example.com.evil.example"} {
			newSoftKey(t).register(t, f, session, ceremonyPlace{origin: origin}).expect(t, http.StatusBadRequest, "invalid_request")
		}
		other.register(t, f, session, ceremonyPlace{}).want(t, http.StatusCreated, "")
		for _, origin := range []string{"https://evil.example", "http://auth.example.com", "https://auth.example.com.evil.example"} {
			other.signIn(t, f, ceremonyPlace{origin: origin}).expect(t, http.StatusUnauthorized, "invalid_credentials")
		}
		tokensFrom(t, other.signIn(t, f, ceremonyPlace{}), u.ID)
	})
}

func passkeyFixture(t *testing.T, topOrigin func(context.Context, string) (bool, error)) *fixture {
	return newFixture(t, authtest.WithConfig(func(c *authkit.Config) {
		c.FrontendURL = passkeyOrigin // the relying party
	}), authtest.WithDeps(func(d *authkit.Deps) { d.PasskeyTopOrigin = topOrigin }))
}

// ceremonyPlace is where the browser ran a ceremony: top-level on the RP's
// origin, or in its iframe on topOrigin's page ("" as Safari reports it).
// origin, when set, is the page the browser reports instead of the RP's.
type ceremonyPlace struct {
	crossOrigin bool
	topOrigin   string
	origin      string
}

// softKey is a passkey authenticator: one ES256 discoverable credential,
// user-verified, no attestation and no signature counter.
type softKey struct {
	key        *ecdsa.PrivateKey
	id         []byte
	userHandle []byte
}

func newSoftKey(t *testing.T) *softKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	noError(t, err)
	id := make([]byte, 32)
	_, err = rand.Read(id)
	noError(t, err)
	return &softKey{key: key, id: id}
}

var b64 = base64.RawURLEncoding

func clientData(t *testing.T, kind, challenge string, at ceremonyPlace) []byte {
	t.Helper()
	origin := at.origin
	if origin == "" {
		origin = passkeyOrigin
	}
	data, err := json.Marshal(struct {
		Type        string `json:"type"`
		Challenge   string `json:"challenge"`
		Origin      string `json:"origin"`
		CrossOrigin bool   `json:"crossOrigin"`
		TopOrigin   string `json:"topOrigin,omitempty"`
	}{kind, challenge, origin, at.crossOrigin, at.topOrigin})
	noError(t, err)
	return data
}

// authenticatorData is rpIdHash, flags (UP, UV, and AT with attested), a
// zero counter and the attested credential.
func (k *softKey) authenticatorData(t *testing.T, attested bool) []byte {
	t.Helper()
	rp := sha256.Sum256([]byte(passkeyRPID))
	out := append([]byte{}, rp[:]...)
	flags := byte(0x01 | 0x04)
	if attested {
		flags |= 0x40
	}
	out = append(out, flags, 0, 0, 0, 0)
	if !attested {
		return out
	}
	pub, err := webauthncbor.Marshal(webauthncose.EC2PublicKeyData{
		PublicKeyData: webauthncose.PublicKeyData{KeyType: int64(webauthncose.EllipticKey), Algorithm: int64(webauthncose.AlgES256)},
		Curve:         1,
		XCoord:        k.key.X.FillBytes(make([]byte, 32)),
		YCoord:        k.key.Y.FillBytes(make([]byte, 32)),
	})
	noError(t, err)
	out = append(out, make([]byte, 16)...)
	out = binary.BigEndian.AppendUint16(out, uint16(len(k.id)))
	out = append(out, k.id...)
	return append(out, pub...)
}

// register adds the key to the signed-in account at /me/passkeys/register.
func (k *softKey) register(t *testing.T, f *fixture, access string, at ceremonyPlace) response {
	t.Helper()
	r := f.call(t, "POST", "/me/passkeys/register/begin", access, nil)
	r.want(t, http.StatusOK, "")
	var begun struct {
		PublicKey struct {
			Challenge string `json:"challenge"`
			User      struct {
				ID string `json:"id"`
			} `json:"user"`
		} `json:"publicKey"`
	}
	decode(t, r.body, &begun)
	handle, err := b64.DecodeString(begun.PublicKey.User.ID)
	noError(t, err)
	attestation, err := webauthncbor.Marshal(map[string]any{"fmt": "none", "attStmt": map[string]any{}, "authData": k.authenticatorData(t, true)})
	noError(t, err)
	r = f.call(t, "POST", "/me/passkeys/register/finish", access, map[string]any{
		"id": b64.EncodeToString(k.id), "rawId": b64.EncodeToString(k.id), "type": "public-key", "clientExtensionResults": map[string]any{},
		"response": map[string]any{
			"clientDataJSON":    b64.EncodeToString(clientData(t, "webauthn.create", begun.PublicKey.Challenge, at)),
			"attestationObject": b64.EncodeToString(attestation),
			"transports":        []string{"internal"},
		},
	})
	if r.status == http.StatusCreated {
		k.userHandle = handle
	}
	return r
}

// signIn is a discoverable passkey sign-in at /passkeys/login.
func (k *softKey) signIn(t *testing.T, f *fixture, at ceremonyPlace) response {
	t.Helper()
	return f.call(t, "POST", "/passkeys/login/finish", "", k.assert(t, beginPasskeyLogin(t, f), at))
}

// beginPasskeyLogin is a sign-in ceremony's challenge.
func beginPasskeyLogin(t *testing.T, f *fixture) string {
	t.Helper()
	r := f.call(t, "POST", "/passkeys/login/begin", "", nil)
	r.want(t, http.StatusOK, "")
	var begun struct {
		PublicKey struct {
			Challenge string `json:"challenge"`
		} `json:"publicKey"`
	}
	decode(t, r.body, &begun)
	return begun.PublicKey.Challenge
}

// assert is the key's freshly signed assertion of challenge, as the browser
// at at hands it to the page.
func (k *softKey) assert(t *testing.T, challenge string, at ceremonyPlace) map[string]any {
	t.Helper()
	data := clientData(t, "webauthn.get", challenge, at)
	auth := k.authenticatorData(t, false)
	hash := sha256.Sum256(data)
	digest := sha256.Sum256(append(append([]byte{}, auth...), hash[:]...))
	sig, err := ecdsa.SignASN1(rand.Reader, k.key, digest[:])
	noError(t, err)
	return map[string]any{
		"id": b64.EncodeToString(k.id), "rawId": b64.EncodeToString(k.id), "type": "public-key", "clientExtensionResults": map[string]any{},
		"response": map[string]any{
			"clientDataJSON":    b64.EncodeToString(data),
			"authenticatorData": b64.EncodeToString(auth),
			"signature":         b64.EncodeToString(sig),
			"userHandle":        b64.EncodeToString(k.userHandle),
		},
	}
}
