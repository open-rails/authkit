package authhttp

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/fxamacker/cbor/v2"
	"github.com/open-rails/authkit/embedded"
	memorystore "github.com/open-rails/authkit/storage/memory"
	"github.com/stretchr/testify/require"
)

func TestPasskeyHTTPIntegrationFullCeremonyAndAssurance(t *testing.T) {
	pool := newServerTestPool(t)
	ctx := context.Background()
	cfg := newServerTestConfig()
	cfg.Passkeys = embedded.PasskeyConfig{
		RPID:             "example.com",
		RPDisplayName:    "Example",
		Origins:          []string{"https://example.com"},
		UserVerification: "preferred",
	}
	srv, err := NewServer(cfg, pool, WithEphemeralStore(memorystore.NewKV(), embedded.EphemeralMemory), WithoutRateLimiter())
	require.NoError(t, err)

	user, err := srv.svc.CreateUser(ctx, uniqueEmail("passkey-full"), "passkeyfull"+uniqueSuffix())
	require.NoError(t, err)
	t.Cleanup(func() { _, _ = pool.Exec(ctx, `DELETE FROM profiles.users WHERE id=$1::uuid`, user.ID) })

	sid, _, _, err := srv.svc.IssueRefreshSession(ctx, user.ID, "test", nil)
	require.NoError(t, err)
	setupToken, _, err := srv.svc.IssueAccessToken(ctx, user.ID, "", map[string]any{"sid": sid})
	require.NoError(t, err)

	authn := newSoftwarePasskeyAuthenticator(t)

	w := serveAuthJSON(srv, http.MethodPost, "/passkeys/register/begin", `{}`, setupToken)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	var creation passkeyCreationOptions
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &creation))
	require.Equal(t, "Example", creation.PublicKey.RP.Name)
	require.Equal(t, "example.com", creation.PublicKey.RP.ID)
	require.Equal(t, "required", creation.PublicKey.AuthenticatorSelection.ResidentKey)
	require.Empty(t, creation.PublicKey.ExcludeCredentials)

	w = serveAuthJSON(srv, http.MethodPost, "/passkeys/register/finish", string(authn.attestation(t, creation)), setupToken)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	var created embedded.Passkey
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &created))
	require.NotEmpty(t, created.ID)
	require.True(t, created.BackupEligible)
	require.True(t, created.BackupState)

	w = serveAuthJSON(srv, http.MethodPost, "/passkeys/register/begin", `{}`, setupToken)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &creation))
	require.Len(t, creation.PublicKey.ExcludeCredentials, 1)
	require.Equal(t, base64URL(authn.credentialID), creation.PublicKey.ExcludeCredentials[0].ID)

	w = serveJSON(srv, http.MethodPost, "/passkeys/login/begin", `{"login":"does-not-exist@example.com"}`)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	var unknown passkeyRequestOptions
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &unknown))
	require.Empty(t, unknown.PublicKey.AllowCredentials)

	w = serveJSON(srv, http.MethodPost, "/passkeys/login/begin", `{"login":"`+*user.Email+`"}`)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	var assertion passkeyRequestOptions
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &assertion))
	// AK2-PK-002: login-begin is ALWAYS discoverable, so even a known identifier
	// yields an empty allowCredentials list (identical to the unknown-identifier
	// response above) — no account-existence probe, no credential-ID leak. The
	// authenticator resolves its resident credential and the ceremony still
	// completes via the user handle (verified by the finish below).
	require.Empty(t, assertion.PublicKey.AllowCredentials)

	w = serveJSON(srv, http.MethodPost, "/passkeys/login/finish", string(authn.assertion(t, assertion, 1)))
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	var tokens struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &tokens))
	require.NotEmpty(t, tokens.RefreshToken)
	claims := unverifiedAccessClaims(t, tokens.AccessToken)
	require.Equal(t, embedded.AssuranceLevelMFA, claims["acr"])
	require.ElementsMatch(t, []any{"swk", "mfa"}, claims["amr"])
	require.NotZero(t, claims["auth_time"])

	w = serveJSON(srv, http.MethodPost, "/passkeys/login/begin", `{}`)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	assertion = passkeyRequestOptions{}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &assertion))
	require.Empty(t, assertion.PublicKey.AllowCredentials)
	w = serveJSON(srv, http.MethodPost, "/passkeys/login/finish", string(authn.assertion(t, assertion, 2)))
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())

	w = serveJSON(srv, http.MethodPost, "/passkeys/login/begin", `{"login":"`+*user.Email+`"}`)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	assertion = passkeyRequestOptions{}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &assertion))
	w = serveJSON(srv, http.MethodPost, "/passkeys/login/finish", string(authn.assertion(t, assertion, 2)))
	require.Equal(t, http.StatusUnauthorized, w.Code, w.Body.String())
	require.Contains(t, w.Body.String(), "invalid_credentials")

	w = serveAuthJSON(srv, http.MethodGet, "/passkeys", `{}`, setupToken)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	var listed struct {
		Passkeys []embedded.Passkey `json:"passkeys"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &listed))
	require.Len(t, listed.Passkeys, 1)
	require.NotNil(t, listed.Passkeys[0].LastUsedAt)
}

func TestPasskeyManagementHTTPIntegration(t *testing.T) {
	pool := newServerTestPool(t)
	ctx := context.Background()
	cfg := newServerTestConfig()
	cfg.Passkeys = embedded.PasskeyConfig{
		RPID:          "example.com",
		RPDisplayName: "Example",
		Origins:       []string{"https://example.com"},
	}
	srv, err := NewServer(cfg, pool, WithEphemeralStore(memorystore.NewKV(), embedded.EphemeralMemory), WithoutRateLimiter())
	require.NoError(t, err)

	user, err := srv.svc.CreateUser(ctx, uniqueEmail("passkey-mgmt"), "passkeymgmt"+uniqueSuffix())
	require.NoError(t, err)
	t.Cleanup(func() { _, _ = pool.Exec(ctx, `DELETE FROM profiles.users WHERE id=$1::uuid`, user.ID) })

	_, err = pool.Exec(ctx, `
		INSERT INTO profiles.user_passkey_handles (user_id, rpid, user_handle)
		VALUES ($1::uuid, 'example.com', $2)
	`, user.ID, []byte("handle"))
	require.NoError(t, err)
	var passkeyID string
	err = pool.QueryRow(ctx, `
		INSERT INTO profiles.user_passkeys (
			user_id, rpid, credential_id, public_key, sign_count, clone_warning, transports,
			authenticator_attachment, backup_eligible, backup_state, user_present, user_verified,
			flags, attestation_type, attestation_fmt, label
		) VALUES (
			$1::uuid, 'example.com', $2, $3, 0, false, ARRAY['internal']::text[],
			'platform', true, true, true, true, $4, 'none', 'none', 'old'
		)
		RETURNING id
	`, user.ID, []byte("credential-id"), []byte("public-key"), []byte{0x1d}).Scan(&passkeyID)
	require.NoError(t, err)

	sid, _, _, err := srv.svc.IssueRefreshSession(ctx, user.ID, "test", nil)
	require.NoError(t, err)
	token, _, err := srv.svc.IssueAccessToken(ctx, user.ID, "", map[string]any{"sid": sid})
	require.NoError(t, err)

	w := serveAuthJSON(srv, http.MethodGet, "/passkeys", `{}`, token)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	var listed struct {
		Passkeys []struct {
			ID    string `json:"id"`
			Label string `json:"label"`
		} `json:"passkeys"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &listed))
	require.Len(t, listed.Passkeys, 1)
	require.Equal(t, passkeyID, listed.Passkeys[0].ID)
	require.Equal(t, "old", listed.Passkeys[0].Label)

	w = serveAuthJSON(srv, http.MethodPatch, "/passkeys/"+passkeyID, `{"label":"new"}`, token)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	w = serveAuthJSON(srv, http.MethodGet, "/passkeys", `{}`, token)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &listed))
	require.Equal(t, "new", listed.Passkeys[0].Label)

	w = serveAuthJSON(srv, http.MethodDelete, "/passkeys/"+passkeyID, `{}`, token)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	w = serveAuthJSON(srv, http.MethodGet, "/passkeys", `{}`, token)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &listed))
	require.Empty(t, listed.Passkeys)
}

type softwarePasskeyAuthenticator struct {
	key          *ecdsa.PrivateKey
	credentialID []byte
	userHandle   []byte
}

type passkeyCreationOptions struct {
	PublicKey struct {
		Challenge string `json:"challenge"`
		RP        struct {
			ID   string `json:"id"`
			Name string `json:"name"`
		} `json:"rp"`
		User struct {
			ID string `json:"id"`
		} `json:"user"`
		AuthenticatorSelection struct {
			ResidentKey string `json:"residentKey"`
		} `json:"authenticatorSelection"`
		ExcludeCredentials []struct {
			ID string `json:"id"`
		} `json:"excludeCredentials"`
	} `json:"publicKey"`
}

type passkeyRequestOptions struct {
	PublicKey struct {
		Challenge        string `json:"challenge"`
		RPID             string `json:"rpId"`
		AllowCredentials []struct {
			ID string `json:"id"`
		} `json:"allowCredentials"`
	} `json:"publicKey"`
}

func newSoftwarePasskeyAuthenticator(t *testing.T) *softwarePasskeyAuthenticator {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	credentialID := make([]byte, 32)
	_, err = rand.Read(credentialID)
	require.NoError(t, err)
	return &softwarePasskeyAuthenticator{key: key, credentialID: credentialID}
}

func (a *softwarePasskeyAuthenticator) attestation(t *testing.T, opts passkeyCreationOptions) []byte {
	t.Helper()
	userHandle, err := base64.RawURLEncoding.DecodeString(opts.PublicKey.User.ID)
	require.NoError(t, err)
	a.userHandle = userHandle

	authData := bytes.NewBuffer(nil)
	authData.Write(rpIDHash(opts.PublicKey.RP.ID))
	authData.WriteByte(0x5d) // user present + user verified + backup flags + attested credential data.
	_ = binary.Write(authData, binary.BigEndian, uint32(0))
	authData.Write(make([]byte, 16))
	_ = binary.Write(authData, binary.BigEndian, uint16(len(a.credentialID)))
	authData.Write(a.credentialID)
	authData.Write(cosePublicKey(t, a.key))

	attObj, err := cbor.Marshal(map[string]any{
		"fmt":      "none",
		"attStmt":  map[string]any{},
		"authData": authData.Bytes(),
	})
	require.NoError(t, err)

	body, err := json.Marshal(map[string]any{
		"id":                     base64URL(a.credentialID),
		"rawId":                  base64URL(a.credentialID),
		"type":                   "public-key",
		"clientExtensionResults": map[string]any{},
		"response": map[string]any{
			"clientDataJSON":    base64URL(clientDataJSON(t, "webauthn.create", opts.PublicKey.Challenge)),
			"attestationObject": base64URL(attObj),
			"transports":        []string{"internal"},
		},
	})
	require.NoError(t, err)
	return body
}

func (a *softwarePasskeyAuthenticator) assertion(t *testing.T, opts passkeyRequestOptions, signCount uint32) []byte {
	t.Helper()
	authData := bytes.NewBuffer(nil)
	authData.Write(rpIDHash(opts.PublicKey.RPID))
	authData.WriteByte(0x1d) // user present + user verified + backup flags.
	_ = binary.Write(authData, binary.BigEndian, signCount)
	clientData := clientDataJSON(t, "webauthn.get", opts.PublicKey.Challenge)
	digest := sha256.Sum256(append(authData.Bytes(), sha256Bytes(clientData)...))
	sig, err := ecdsa.SignASN1(rand.Reader, a.key, digest[:])
	require.NoError(t, err)

	body, err := json.Marshal(map[string]any{
		"id":                     base64URL(a.credentialID),
		"rawId":                  base64URL(a.credentialID),
		"type":                   "public-key",
		"clientExtensionResults": map[string]any{},
		"response": map[string]any{
			"authenticatorData": base64URL(authData.Bytes()),
			"clientDataJSON":    base64URL(clientData),
			"signature":         base64URL(sig),
			"userHandle":        base64URL(a.userHandle),
		},
	})
	require.NoError(t, err)
	return body
}

func clientDataJSON(t *testing.T, ceremonyType, challenge string) []byte {
	t.Helper()
	body, err := json.Marshal(map[string]any{
		"type":        ceremonyType,
		"challenge":   challenge,
		"origin":      "https://example.com",
		"crossOrigin": false,
	})
	require.NoError(t, err)
	return body
}

func cosePublicKey(t *testing.T, key *ecdsa.PrivateKey) []byte {
	t.Helper()
	// Uncompressed P-256 point encoding: 0x04 || X(32) || Y(32).
	pub, err := key.PublicKey.Bytes()
	require.NoError(t, err)
	x := pub[1:33]
	y := pub[33:65]
	out, err := cbor.Marshal(map[int]any{
		1:  2,  // kty: EC2
		3:  -7, // alg: ES256
		-1: 1,  // crv: P-256
		-2: x,
		-3: y,
	})
	require.NoError(t, err)
	return out
}

func rpIDHash(rpID string) []byte {
	sum := sha256.Sum256([]byte(rpID))
	return sum[:]
}

func sha256Bytes(in []byte) []byte {
	sum := sha256.Sum256(in)
	return sum[:]
}

func base64URL(in []byte) string {
	return base64.RawURLEncoding.EncodeToString(in)
}
