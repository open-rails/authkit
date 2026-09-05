// Package passkeytest is a software WebAuthn authenticator for passkey
// integration tests: it answers real registration and assertion ceremonies
// with a P-256 key, so tests exercise the production ceremony code paths.
package passkeytest

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"testing"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/protocol/webauthncbor"
	"github.com/stretchr/testify/require"
)

// Authenticator is one resident (discoverable) credential. The flag fields are
// applied to every response it produces; defaults model a synced platform
// passkey with user verification.
type Authenticator struct {
	Key            *ecdsa.PrivateKey
	CredentialID   []byte
	UserHandle     []byte
	Origin         string
	UserVerified   bool
	BackupEligible bool
	BackupState    bool
}

func New(t testing.TB, origin string) *Authenticator {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	id := make([]byte, 32)
	_, err = rand.Read(id)
	require.NoError(t, err)
	return &Authenticator{Key: key, CredentialID: id, Origin: origin, UserVerified: true, BackupEligible: true, BackupState: true}
}

// Register answers an in-process creation ceremony.
func (a *Authenticator) Register(t testing.TB, creation *protocol.CredentialCreation) []byte {
	t.Helper()
	return a.Attestation(t, creation.Response.RelyingParty.ID, UserHandle(t, creation.Response.User.ID), creation.Response.Challenge.String())
}

// Assert answers an in-process assertion ceremony.
func (a *Authenticator) Assert(t testing.TB, assertion *protocol.CredentialAssertion, signCount uint32) []byte {
	t.Helper()
	return a.Assertion(t, assertion.Response.RelyingPartyID, assertion.Response.Challenge.String(), signCount)
}

// Attestation builds a `none`-format registration response for the ceremony
// parameters, binding the credential to userHandle.
func (a *Authenticator) Attestation(t testing.TB, rpID string, userHandle []byte, challenge string) []byte {
	t.Helper()
	a.UserHandle = userHandle
	authData := bytes.NewBuffer(nil)
	authData.Write(rpIDHash(rpID))
	authData.WriteByte(a.flags() | byte(protocol.FlagAttestedCredentialData))
	_ = binary.Write(authData, binary.BigEndian, uint32(0))
	authData.Write(make([]byte, 16))
	_ = binary.Write(authData, binary.BigEndian, uint16(len(a.CredentialID)))
	authData.Write(a.CredentialID)
	authData.Write(cosePublicKey(t, a.Key))

	attObj, err := webauthncbor.Marshal(map[string]any{
		"fmt":      "none",
		"attStmt":  map[string]any{},
		"authData": authData.Bytes(),
	})
	require.NoError(t, err)

	body, err := json.Marshal(map[string]any{
		"id":                     b64(a.CredentialID),
		"rawId":                  b64(a.CredentialID),
		"type":                   "public-key",
		"clientExtensionResults": map[string]any{},
		"response": map[string]any{
			"clientDataJSON":    b64(a.clientData(t, "webauthn.create", challenge)),
			"attestationObject": b64(attObj),
			"transports":        []string{"internal"},
		},
	})
	require.NoError(t, err)
	return body
}

// Assertion signs a discoverable assertion for the ceremony parameters with
// the given signature counter (0 models a synced passkey).
func (a *Authenticator) Assertion(t testing.TB, rpID, challenge string, signCount uint32) []byte {
	t.Helper()
	authData := bytes.NewBuffer(nil)
	authData.Write(rpIDHash(rpID))
	authData.WriteByte(a.flags())
	_ = binary.Write(authData, binary.BigEndian, signCount)
	clientData := a.clientData(t, "webauthn.get", challenge)
	clientHash := sha256.Sum256(clientData)
	digest := sha256.Sum256(append(authData.Bytes(), clientHash[:]...))
	sig, err := ecdsa.SignASN1(rand.Reader, a.Key, digest[:])
	require.NoError(t, err)

	body, err := json.Marshal(map[string]any{
		"id":                     b64(a.CredentialID),
		"rawId":                  b64(a.CredentialID),
		"type":                   "public-key",
		"clientExtensionResults": map[string]any{},
		"response": map[string]any{
			"authenticatorData": b64(authData.Bytes()),
			"clientDataJSON":    b64(clientData),
			"signature":         b64(sig),
			"userHandle":        b64(a.UserHandle),
		},
	})
	require.NoError(t, err)
	return body
}

// UserHandle decodes the user entity id of a creation ceremony, whether it is
// still the in-process byte form or the base64url string a JSON round trip made it.
func UserHandle(t testing.TB, id any) []byte {
	t.Helper()
	switch v := id.(type) {
	case protocol.URLEncodedBase64:
		return []byte(v)
	case []byte:
		return v
	case string:
		out, err := base64.RawURLEncoding.DecodeString(v)
		require.NoError(t, err)
		return out
	}
	t.Fatalf("passkeytest: unsupported user id type %T", id)
	return nil
}

func (a *Authenticator) flags() byte {
	f := protocol.FlagUserPresent
	if a.UserVerified {
		f |= protocol.FlagUserVerified
	}
	if a.BackupEligible {
		f |= protocol.FlagBackupEligible
	}
	if a.BackupState {
		f |= protocol.FlagBackupState
	}
	return byte(f)
}

func (a *Authenticator) clientData(t testing.TB, ceremonyType, challenge string) []byte {
	t.Helper()
	body, err := json.Marshal(map[string]any{
		"type":        ceremonyType,
		"challenge":   challenge,
		"origin":      a.Origin,
		"crossOrigin": false,
	})
	require.NoError(t, err)
	return body
}

func cosePublicKey(t testing.TB, key *ecdsa.PrivateKey) []byte {
	t.Helper()
	pub, err := key.PublicKey.Bytes()
	require.NoError(t, err)
	out, err := webauthncbor.Marshal(map[int]any{
		1:  2,  // kty: EC2
		3:  -7, // alg: ES256
		-1: 1,  // crv: P-256
		-2: pub[1:33],
		-3: pub[33:65],
	})
	require.NoError(t, err)
	return out
}

func rpIDHash(rpID string) []byte {
	sum := sha256.Sum256([]byte(rpID))
	return sum[:]
}

func b64(in []byte) string { return base64.RawURLEncoding.EncodeToString(in) }
