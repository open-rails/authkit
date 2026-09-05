package authhttp

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/open-rails/authkit/embedded"
	authcore "github.com/open-rails/authkit/internal/authcore"
	"github.com/open-rails/authkit/internal/passkeytest"
	"github.com/open-rails/authkit/internal/testdb"
	"github.com/stretchr/testify/require"
)

func TestPasskeyHTTPIntegrationFullCeremonyAndAssurance(t *testing.T) {
	forEachStore(t, testPasskeyFullCeremonyAndAssurance)
}

func testPasskeyFullCeremonyAndAssurance(t *testing.T, store ephemeralStore) {
	pool := testdb.Pool(t)
	ctx := context.Background()
	cfg := newServerTestConfig()
	cfg.Passkeys = embedded.PasskeyConfig{
		RPID:             "example.com",
		RPDisplayName:    "Example",
		Origins:          []string{"https://example.com"},
		UserVerification: "preferred",
	}
	srv, err := newServer(newServerClient(t, cfg, pool, store.engineOpts()...), WithoutRateLimiter())
	require.NoError(t, err)

	user, err := srv.svc.CreateUser(ctx, uniqueEmail("passkey-full"), "passkeyfull"+uniqueSuffix())
	require.NoError(t, err)
	t.Cleanup(func() { _, _ = pool.Exec(ctx, `DELETE FROM profiles.users WHERE id=$1::uuid`, user.ID) })

	sid, _, _, err := srv.svc.IssueRefreshSession(ctx, user.ID, "test", nil)
	require.NoError(t, err)
	setupToken, _, err := srv.svc.MintAccessToken(ctx, user.ID, map[string]any{"sid": sid})
	require.NoError(t, err)

	authn := passkeytest.New(t, "https://example.com")

	w := serveAuthJSON(srv, http.MethodPost, "/passkeys/register/begin", `{}`, setupToken)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	var creation passkeyCreationOptions
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &creation))
	require.Equal(t, "Example", creation.PublicKey.RP.Name)
	require.Equal(t, "example.com", creation.PublicKey.RP.ID)
	require.Equal(t, "required", creation.PublicKey.AuthenticatorSelection.ResidentKey)
	require.Empty(t, creation.PublicKey.ExcludeCredentials)

	w = serveAuthJSON(srv, http.MethodPost, "/passkeys/register/finish", string(attest(t, authn, creation)), setupToken)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	var created authcore.Passkey
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &created))
	require.NotEmpty(t, created.ID)
	require.True(t, created.BackupEligible)
	require.True(t, created.BackupState)

	w = serveAuthJSON(srv, http.MethodPost, "/passkeys/register/begin", `{}`, setupToken)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &creation))
	require.Len(t, creation.PublicKey.ExcludeCredentials, 1)
	require.Equal(t, base64.RawURLEncoding.EncodeToString(authn.CredentialID), creation.PublicKey.ExcludeCredentials[0].ID)

	w = serveJSON(srv, http.MethodPost, "/passkeys/login/begin", `{"identifier":"does-not-exist@example.com"}`)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	var unknown passkeyRequestOptions
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &unknown))
	require.Empty(t, unknown.PublicKey.AllowCredentials)

	w = serveJSON(srv, http.MethodPost, "/passkeys/login/begin", `{"identifier":"`+*user.Email+`"}`)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	var assertion passkeyRequestOptions
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &assertion))
	// AK2-PK-002: login-begin is ALWAYS discoverable, so even a known identifier
	// yields an empty allowCredentials list (identical to the unknown-identifier
	// response above) — no account-existence probe, no credential-ID leak. The
	// authenticator resolves its resident credential and the ceremony still
	// completes via the user handle (verified by the finish below).
	require.Empty(t, assertion.PublicKey.AllowCredentials)

	firstAssertion := string(assert(t, authn, assertion, 1))
	w = serveJSON(srv, http.MethodPost, "/passkeys/login/finish", firstAssertion)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	var tokens struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &tokens))
	require.NotEmpty(t, tokens.RefreshToken)
	claims := unverifiedAccessClaims(t, tokens.AccessToken)
	require.Equal(t, authcore.AssuranceLevelMFA, claims["acr"])
	require.ElementsMatch(t, []any{"swk", "mfa"}, claims["amr"])
	require.NotZero(t, claims["auth_time"])

	// #288/9: the identical assertion replayed — the ceremony was consumed on
	// the first finish, so the replay must be rejected.
	replay := serveJSON(srv, http.MethodPost, "/passkeys/login/finish", firstAssertion)
	require.Equal(t, http.StatusUnauthorized, replay.Code, replay.Body.String())

	w = serveJSON(srv, http.MethodPost, "/passkeys/login/begin", `{}`)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	assertion = passkeyRequestOptions{}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &assertion))
	require.Empty(t, assertion.PublicKey.AllowCredentials)
	w = serveJSON(srv, http.MethodPost, "/passkeys/login/finish", string(assert(t, authn, assertion, 2)))
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())

	w = serveJSON(srv, http.MethodPost, "/passkeys/login/begin", `{"identifier":"`+*user.Email+`"}`)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	assertion = passkeyRequestOptions{}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &assertion))
	w = serveJSON(srv, http.MethodPost, "/passkeys/login/finish", string(assert(t, authn, assertion, 2)))
	require.Equal(t, http.StatusUnauthorized, w.Code, w.Body.String())
	require.Contains(t, w.Body.String(), "invalid_credentials")

	w = serveAuthJSON(srv, http.MethodGet, "/passkeys", `{}`, setupToken)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	var listed struct {
		Data []authcore.Passkey `json:"data"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &listed))
	require.Len(t, listed.Data, 1)
	require.NotNil(t, listed.Data[0].LastUsedAt)
}

func TestPasskeyManagementHTTPIntegration(t *testing.T) {
	pool := testdb.Pool(t)
	ctx := context.Background()
	cfg := newServerTestConfig()
	cfg.Passkeys = embedded.PasskeyConfig{
		RPID:          "example.com",
		RPDisplayName: "Example",
		Origins:       []string{"https://example.com"},
	}
	srv, err := newServer(newServerClient(t, cfg, pool), WithoutRateLimiter())
	require.NoError(t, err)

	user, err := srv.svc.CreateUser(ctx, uniqueEmail("passkey-mgmt"), "passkeymgmt"+uniqueSuffix())
	require.NoError(t, err)
	t.Cleanup(func() { _, _ = pool.Exec(ctx, `DELETE FROM profiles.users WHERE id=$1::uuid`, user.ID) })

	_, err = pool.Exec(ctx, `
		INSERT INTO profiles.user_passkey_handles (user_id, user_handle)
		VALUES ($1::uuid, $2)
	`, user.ID, []byte("handle"))
	require.NoError(t, err)
	var passkeyID string
	err = pool.QueryRow(ctx, `
		INSERT INTO profiles.user_passkeys (
			user_id, rpid, credential_id, public_key, sign_count, clone_warning, transports,
			authenticator_attachment, backup_eligible, backup_state,
			flags, attestation_type, attestation_fmt, label
		) VALUES (
			$1::uuid, 'example.com', $2, $3, 0, false, ARRAY['internal']::text[],
			'platform', true, true, $4, 'none', 'none', 'old'
		)
		RETURNING id
	`, user.ID, []byte("credential-id"), []byte("public-key"), []byte{0x1d}).Scan(&passkeyID)
	require.NoError(t, err)

	sid, _, _, err := srv.svc.IssueRefreshSession(ctx, user.ID, "test", nil)
	require.NoError(t, err)
	token, _, err := srv.svc.MintAccessToken(ctx, user.ID, map[string]any{"sid": sid})
	require.NoError(t, err)

	w := serveAuthJSON(srv, http.MethodGet, "/passkeys", `{}`, token)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	var listed struct {
		Data []struct {
			ID    string `json:"id"`
			Label string `json:"label"`
		} `json:"data"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &listed))
	require.Len(t, listed.Data, 1)
	require.Equal(t, passkeyID, listed.Data[0].ID)
	require.Equal(t, "old", listed.Data[0].Label)

	w = serveAuthJSON(srv, http.MethodPatch, "/passkeys/"+passkeyID, `{"label":"new"}`, token)
	require.Equal(t, http.StatusNoContent, w.Code, w.Body.String())
	w = serveAuthJSON(srv, http.MethodGet, "/passkeys", `{}`, token)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &listed))
	require.Equal(t, "new", listed.Data[0].Label)

	w = serveAuthJSON(srv, http.MethodDelete, "/passkeys/"+passkeyID, `{}`, token)
	require.Equal(t, http.StatusNoContent, w.Code, w.Body.String())
	w = serveAuthJSON(srv, http.MethodGet, "/passkeys", `{}`, token)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &listed))
	require.Empty(t, listed.Data)
}

// The wire shapes the browser sees, decoded only as far as the tests assert on them.
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

func attest(t *testing.T, authn *passkeytest.Authenticator, opts passkeyCreationOptions) []byte {
	t.Helper()
	return authn.Attestation(t, opts.PublicKey.RP.ID, passkeytest.UserHandle(t, opts.PublicKey.User.ID), opts.PublicKey.Challenge)
}

func assert(t *testing.T, authn *passkeytest.Authenticator, opts passkeyRequestOptions, signCount uint32) []byte {
	t.Helper()
	return authn.Assertion(t, opts.PublicKey.RPID, opts.PublicKey.Challenge, signCount)
}
