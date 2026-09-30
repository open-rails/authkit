package engine

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"testing"

	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/testdb"
	"github.com/open-rails/authkit/internal/testidp"
	"github.com/stretchr/testify/require"
)

// Account creation consumes its invitation in the same transaction: when the
// consume fails, no registration flow leaves an account or a spent invitation
// behind.
func TestRegistrationRollsBackWhenInviteConsumeFails(t *testing.T) {
	pg := testdb.ScratchPostgres(t)
	cfg := newServerTestConfig()
	cfg.Registration.PasswordlessLogin, cfg.Registration.PasswordlessAutoRegistration = true, true
	cfg.Registration.Verification = iam.RegistrationVerificationRequired
	cfg.Registration.NativeUserMode = iam.RegistrationModeInviteOnly
	f := newAccountFlow(t, pg.Pool, cfg)
	inviter, _ := createAccountInvite(t, f.service, pg.Pool, uniqueEmail("unused"))
	pool, ctx := fixtureBackend(f.service.Backend()).pg, t.Context()
	_, err := pool.Exec(ctx, `CREATE FUNCTION registration_failure() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'injected invite consume failure'; END $$; CREATE TRIGGER registration_failure BEFORE UPDATE OF consumed_at ON account_registration_invites FOR EACH ROW EXECUTE FUNCTION registration_failure()`)
	require.NoError(t, err)
	defer func() {
		_, err := pool.Exec(ctx, `DROP TRIGGER registration_failure ON account_registration_invites; DROP FUNCTION registration_failure()`)
		require.NoError(t, err)
	}()
	for _, flow := range []string{"email", "sms", "passwordless", "oidc", "oauth2"} {
		email, identifier := uniqueEmail("rollback"), ""
		identifier = email
		if flow == "sms" {
			identifier = uniquePhone()
		}
		invite, err := f.service.Backend().CreateAccountInvite(ctx, iam.UserActor(inviter), iam.NewAccountInvite{Email: email})
		require.NoError(t, err)
		var failed flowResponse
		if flow == "oidc" || flow == "oauth2" {
			idp := testidp.New(t)
			provider := idp.OAuth2("idp")
			if flow == "oidc" {
				provider = idp.OIDC("idp")
			}
			f.service.SetProviders(provider)
			f.mount()
			failed = providerSignUp(f, idp, testidp.Identity{Subject: "rollback-" + uniqueSuffix(), Email: email, EmailVerified: true}, invite.Code)
		} else {
			path := "/register"
			body := map[string]any{"identifier": identifier, "account_invite_token": invite.Code}
			if flow == "passwordless" {
				path = "/passwordless/start"
				body["mode"] = "both"
			} else {
				body["username"] = "roll" + uniqueSuffix()
				body["password"] = "Correct-horse-battery-1"
			}
			f.expect(202, f.post(path, body))
			confirm := "/verify/confirm"
			if flow == "passwordless" {
				confirm = "/passwordless/confirm"
			}
			failed = f.post(confirm, map[string]any{"identifier": identifier, "code": f.verifyCode(flow == "sms")})
		}
		require.GreaterOrEqual(t, failed.status, 400, flow+failed.raw)
		var exists, consumed bool
		require.NoError(t, pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM users WHERE email=$1 OR phone_number=$2),(SELECT consumed_at IS NOT NULL FROM account_registration_invites WHERE id=$3::uuid)`, email, identifier, invite.ID).Scan(&exists, &consumed))
		require.False(t, exists, flow)
		require.False(t, consumed, flow)
	}
}

// providerSignUp signs id in at f's provider "idp" as a page does, carrying
// invite: a JSON start, the IdP's redirect back, and the JSON callback.
func providerSignUp(f *accountFlow, idp *testidp.IdP, id testidp.Identity, invite string) flowResponse {
	t := f.t
	t.Helper()
	begin, err := json.Marshal(map[string]string{"account_invite_token": invite})
	require.NoError(t, err)
	start, err := f.server.Client().Post(f.server.URL+"/oidc/idp/login", "application/json", bytes.NewReader(begin))
	require.NoError(t, err)
	defer start.Body.Close()
	require.Equal(t, http.StatusOK, start.StatusCode)
	var begun struct {
		AuthURL string `json:"auth_url"`
	}
	require.NoError(t, json.NewDecoder(start.Body).Decode(&begun))
	query := idp.Redirect(t, begun.AuthURL, id)
	query.Set("format", "json")
	req, err := http.NewRequest(http.MethodGet, f.server.URL+"/oidc/idp/callback?"+query.Encode(), nil)
	require.NoError(t, err)
	for _, cookie := range start.Cookies() {
		req.AddCookie(cookie)
	}
	callback, err := f.server.Client().Do(req)
	require.NoError(t, err)
	defer callback.Body.Close()
	raw, err := io.ReadAll(callback.Body)
	require.NoError(t, err)
	return flowResponse{status: callback.StatusCode, raw: string(raw)}
}
