package engine

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/passkeytest"
	"github.com/open-rails/authkit/internal/testdb"
	"github.com/stretchr/testify/require"
)

// A passkey sign-in that verified its assertion completes while the passkey is
// deleted: the deletion waits for the session insert, and the session it
// already authorized stands, a user-verifying passkey session under required
// 2FA with an MFA-required role.
func TestPasskeyLoginCompletesWhileItsPasskeyIsDeleted(t *testing.T) {
	pg := testdb.ScratchPostgres(t)
	cfg := newServerTestConfig()
	cfg.TwoFactor.Mode = iam.TwoFactorRequired
	cfg.Passkeys = PasskeyConfig{RPID: "app.example", Origins: []string{"https://app.example"}}
	cfg.Roles = RoleConfig{Roles: []Role{{Persona: "root", Name: "admin", Permissions: []string{"root:*"}}}}
	f := newAccountFlow(t, pg.Pool, cfg)
	ctx := t.Context()
	// The role came while 2FA was off.
	bootstrapCfg := cfg
	bootstrapCfg.TwoFactor.Mode = iam.TwoFactorDisabled
	bootstrap := newServerClient(t, bootstrapCfg, pg.Pool)
	_, err := bootstrap.ensureRootGroup(ctx)
	require.NoError(t, err)
	user, err := bootstrap.createUser(ctx, uniqueEmail("uv-role"), "uv"+uniqueSuffix())
	require.NoError(t, err)
	require.NoError(t, bootstrap.markEmailVerified(ctx, user.ID))
	grantRole(t, bootstrap, iam.RootGroup(), iam.UserSubject(user.ID), "admin")
	authn := passkeytest.New(t, "https://app.example")
	creation, err := f.service.Backend().BeginPasskeyRegistration(ctx, user.ID)
	require.NoError(t, err)
	created, err := f.service.Backend().FinishPasskeyRegistration(ctx, user.ID, authn.Register(t, creation))
	require.NoError(t, err)

	start := f.expect(200, f.post("/passkeys/login/begin", map[string]any{}))
	var assertion protocol.CredentialAssertion
	require.NoError(t, json.Unmarshal([]byte(start.raw), &assertion))
	proof := json.RawMessage(authn.Assert(t, &assertion, 1))
	completed := f.completeWhileRevoking(user.ID, func() flowResponse { return f.post("/passkeys/login/finish", proof) }, func(ctx context.Context) error {
		return f.service.Backend().DeletePasskey(ctx, user.ID, created.ID)
	})
	f.expect(200, completed)
	f.session(completed.TokenSet, "swk", "mfa")
}
