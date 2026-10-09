package engine

import (
	"testing"

	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/config"
	"github.com/open-rails/authkit/internal/testdb"
	"github.com/open-rails/authkit/internal/testidp"
	"github.com/open-rails/authkit/provider"
	"github.com/stretchr/testify/require"
)

// Account creation consumes its invitation in the same transaction: when the
// consume fails, no registration flow leaves an account or a spent invitation
// behind.
func TestRegistrationRollsBackWhenInviteConsumeFails(t *testing.T) {
	pg := testdb.ScratchPostgres(t)
	cfg := testConfig()
	cfg.Registration.PasswordlessLogin, cfg.Registration.PasswordlessAutoRegistration = true, true
	cfg.Registration.Verification = iam.RegistrationVerificationRequired
	cfg.Registration.NativeUserMode = iam.RegistrationModeInviteOnly
	idps := map[string]*testidp.IdP{"oidc": testidp.New(t), "oauth2": testidp.New(t)}
	f := newAccountFlow(t, pg.Pool, cfg, config.Deps{Providers: []provider.Provider{idps["oidc"].OIDC("oidc"), idps["oauth2"].OAuth2("oauth2")}})
	pool, ctx := pg.Pool, t.Context()
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
		invite, err := f.engine.CreateInvitation(ctx, iam.SystemIdentity(), iam.RootGroup(), iam.NewInvitation{Email: email})
		require.NoError(t, err)
		var failed flowResponse
		if idp, ok := idps[flow]; ok {
			failed = f.providerSignIn(idp, flow, testidp.Identity{Subject: "rollback-" + uniqueSuffix(), Email: email, EmailVerified: true}, invite.Code)
		} else {
			path := "/register"
			body := map[string]any{"identifier": identifier, "invite_code": invite.Code}
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
			outbox := f.email
			if flow == "sms" {
				outbox = f.sms
			}
			failed = f.post(confirm, map[string]any{"identifier": identifier, "code": sentCode(t, outbox, iam.MessageVerification)})
		}
		require.GreaterOrEqual(t, failed.status, 400, flow+failed.raw)
		var exists, consumed bool
		require.NoError(t, pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM users WHERE email=$1 OR phone_number=$2),(SELECT consumed_at IS NOT NULL FROM account_registration_invites WHERE id=$3::uuid)`, email, identifier, invite.Invitation.ID).Scan(&exists, &consumed))
		require.False(t, exists, flow)
		require.False(t, consumed, flow)
	}
}
