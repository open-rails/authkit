package authcore

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	memorystore "github.com/open-rails/authkit/storage/memory"
)

func TestPasskeyLoginRejectsValidNonUVAssertion(t *testing.T) {
	pool := testPG(t)
	ctx := context.Background()
	cfg := Config{
		Token: TokenConfig{
			Issuer:            "https://example.org",
			IssuedAudiences:   []string{"test-app"},
			ExpectedAudiences: []string{"test-app"},
		},
		Passkeys: PasskeyConfig{
			RPID:          "example.org",
			RPDisplayName: "Example",
			Origins:       []string{"https://example.org"},
		},
	}
	svc, err := NewFromConfig(cfg, pool, WithEphemeralStore(memorystore.NewKV(), EphemeralMemory))
	if err != nil {
		t.Fatalf("new service: %v", err)
	}

	user, err := svc.CreateUser(ctx, "passkey-vector@test.example", "passkeyvector")
	if err != nil {
		t.Fatalf("create user: %v", err)
	}
	t.Cleanup(func() { _, _ = pool.Exec(ctx, `DELETE FROM profiles.users WHERE id=$1::uuid`, user.ID) })

	body, challenge, credentialID, publicKey := passkeyAssertionVectorNoUV(t)
	handle := []byte("test-user-id")
	if _, err := pool.Exec(ctx, `
		INSERT INTO profiles.user_passkey_handles (user_id, rpid, user_handle)
		VALUES ($1::uuid, 'example.org', $2)
		ON CONFLICT DO NOTHING
	`, user.ID, handle); err != nil {
		t.Fatalf("insert handle: %v", err)
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO profiles.user_passkeys (
			user_id, rpid, credential_id, public_key, sign_count, clone_warning, transports,
			authenticator_attachment, backup_eligible, backup_state, user_present, user_verified,
			flags, attestation_type, attestation_fmt
		) VALUES (
			$1::uuid, 'example.org', $2, $3, 0, false, '{}',
			'', true, true, true, false, $4, 'none', 'none'
		)
	`, user.ID, credentialID, publicKey, []byte{byte(protocol.FlagUserPresent | protocol.FlagBackupEligible | protocol.FlagBackupState)}); err != nil {
		t.Fatalf("insert passkey: %v", err)
	}
	session := webauthn.SessionData{
		Challenge:            challenge,
		RelyingPartyID:       "example.org",
		UserID:               handle,
		AllowedCredentialIDs: [][]byte{credentialID},
		UserVerification:     protocol.VerificationPreferred,
	}
	rawSession, err := json.Marshal(session)
	if err != nil {
		t.Fatalf("marshal session: %v", err)
	}
	if err := svc.storePasskeyCeremony(ctx, challenge, passkeyCeremonyData{Session: rawSession}, time.Minute); err != nil {
		t.Fatalf("store ceremony: %v", err)
	}

	_, err = svc.FinishPasskeyLogin(ctx, body, "test", nil)
	if !errors.Is(err, ErrPasskeyUserVerificationRequired) {
		t.Fatalf("FinishPasskeyLogin err = %v, want ErrPasskeyUserVerificationRequired", err)
	}
}

func passkeyAssertionVectorNoUV(t *testing.T) (body []byte, challenge string, credentialID []byte, publicKey []byte) {
	t.Helper()
	const (
		authenticatorDataHex = "bfabc37432958b063360d3ad6461c9c4735ae7f8edd46592a5e0f01452b2e4b51900000000"
		clientDataJSONHex    = "7b2274797065223a22776562617574686e2e676574222c226368616c6c656e6765223a224f63446e55685158756c5455506f334a5558543049393770767a7a59425039745a63685879617630314167222c226f726967696e223a2268747470733a2f2f6578616d706c652e6f7267222c2263726f73734f726967696e223a66616c73657d"
		signatureHex         = "3046022100f50a4e2e4409249c4a853ba361282f09841df4dd4547a13a87780218deffcd380221008480ac0f0b93538174f575bf11a1dd5d78c6e486013f937295ea13653e331e87"
		credentialIDHex      = "f91f391db4c9b2fde0ea70189cba3fb63f579ba6122b33ad94ff3ec330084be4"
		challengeHex         = "39c0e7521417ba54d43e8dc95174f423dee9bf3cd804ff6d65c857c9abf4d408"
		credentialPubKeyHex  = "a5010203262001215820afefa16f97ca9b2d23eb86ccb64098d20db90856062eb249c33a9b672f26df61225820930a56b87a2fca66334b03458abf879717c12cc68ed73290af2e2664796b9220"
	)
	credentialID = decodeHexForTest(t, credentialIDHex)
	publicKey = decodeHexForTest(t, credentialPubKeyHex)
	challenge = base64.RawURLEncoding.EncodeToString(decodeHexForTest(t, challengeHex))
	id := base64.RawURLEncoding.EncodeToString(credentialID)
	body, err := json.Marshal(map[string]any{
		"id":    id,
		"rawId": id,
		"type":  "public-key",
		"response": map[string]any{
			"authenticatorData": base64.RawURLEncoding.EncodeToString(decodeHexForTest(t, authenticatorDataHex)),
			"clientDataJSON":    base64.RawURLEncoding.EncodeToString(decodeHexForTest(t, clientDataJSONHex)),
			"signature":         base64.RawURLEncoding.EncodeToString(decodeHexForTest(t, signatureHex)),
		},
	})
	if err != nil {
		t.Fatalf("marshal vector: %v", err)
	}
	return body, challenge, credentialID, publicKey
}

func decodeHexForTest(t *testing.T, value string) []byte {
	t.Helper()
	out, err := hex.DecodeString(value)
	if err != nil {
		t.Fatalf("decode hex: %v", err)
	}
	return out
}
