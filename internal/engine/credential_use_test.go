package engine

import (
	"context"
	"testing"

	"github.com/open-rails/authkit/auth"
	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/config"
	"github.com/open-rails/authkit/internal/errmodel"
	"github.com/open-rails/authkit/internal/ident"
	"github.com/open-rails/authkit/internal/testdb"
	"github.com/stretchr/testify/require"
)

// Neither fleet starts. Cleanup can stay queued indefinitely; credentials
// already used successfully must still stop at the committed authority change.
func TestInvitationsAndApplicationsRejectPeerRevocationBeforeSweep(t *testing.T) {
	for _, inherited := range []bool{false, true} {
		t.Run(map[bool]string{false: "direct group authority", true: "inherited tenant authority"}[inherited], func(t *testing.T) {
			checkPeerCredentialRevocation(t, inherited)
		})
	}
}

func checkPeerCredentialRevocation(t *testing.T, inherited bool) {
	pg := testdb.EmptyScratchPostgres(t)
	issuers := []string{"https://credential-a.test", "https://credential-b.test"}
	apps := make([]*Engine, 2)
	for i, schema := range []string{"credential_a_jobs", "credential_b_jobs"} {
		cfg := credentialConfig(credentialRoles(false))
		cfg.Token.Issuer, cfg.Token.AccountIssuers = issuers[i], issuers
		cfg.Database.RiverSchema = schema
		var err error
		apps[i], err = New(t.Context(), cfg, config.Deps{Postgres: pg.Pool})
		require.NoError(t, err)
		t.Cleanup(func() { _ = apps[i].Close(context.Background()) })
	}
	a, b := apps[0], apps[1]
	f := &credentialFixture{t: t, e: b, pool: pg.Pool}
	f.founder = f.user("founder")
	var err error
	f.acmeID, err = seedGroup(t.Context(), b, ident.Persona("org"), f.founder.ID)
	require.NoError(t, err)
	f.acme = iam.GroupByID(f.acmeID)
	creator := f.user("creator")
	if inherited {
		tenant := iam.GroupByID(testdb.DefaultTenantID.String())
		grantRole(t, b, tenant, f.founder, "owner")
		grantRole(t, b, tenant, creator, "owner")
	} else {
		grantRole(t, b, f.acme, creator, "manager")
	}
	grantRole(t, b, iam.RootGroup(), creator, "inviter")
	issued := f.issue(t, creator, "manager", true)
	control := f.issue(t, f.founder, "manager", false)
	system, err := b.CreateAPIKey(t.Context(), iam.SystemIdentity(), f.acme, iam.NewAPIKey{Name: "system", Role: f.role("member")})
	require.NoError(t, err)
	app, err := b.UpsertRemoteApplication(t.Context(), iam.UserIdentity(creator.ID), f.acme,
		iam.RemoteApplication{Issuer: "https://delegated-app.test", JWKSURI: "https://delegated-app.test/jwks", Enabled: true})
	require.NoError(t, err)
	grantRole(t, b, f.acme, iam.RemoteApplicationSubject(app.ID), "member")
	perm := ident.Perm("org:catalog:read")
	allowed, err := b.Can(t.Context(), iam.ApplicationIdentity(app.ID), f.acme, perm)
	require.NoError(t, err)
	require.True(t, allowed)
	permissions, err := b.EffectivePermissions(t.Context(), iam.ApplicationIdentity(app.ID), []iam.GroupRef{f.acme})
	require.NoError(t, err)
	require.NotEmpty(t, permissions)
	// A resource-token Verified retains the original application snapshot;
	// its next permission check still goes through live application authority.
	verified := resourceVerified{s: b, issuer: issuers[1], bound: auth.Scope{Authority: issuers[1], ID: f.acmeID},
		access: ResourceAccess{Application: &app, Permissions: []string{perm.String()}}}
	allowed, err = verified.Can(t.Context(), verified.bound, perm.String())
	require.NoError(t, err)
	require.True(t, allowed)

	// A judges its own credentials only; B's rows deliberately remain live.
	if inherited {
		require.NoError(t, unassignRole(t.Context(), a, iam.SystemIdentity(), iam.GroupByID(testdb.DefaultTenantID.String()), creator, "owner"))
	} else {
		require.NoError(t, assignRole(t.Context(), a, iam.SystemIdentity(), f.acme, creator, "member"))
	}
	require.NoError(t, unassignRole(t.Context(), a, iam.SystemIdentity(), iam.RootGroup(), creator, "inviter"))
	var revoked bool
	require.NoError(t, b.pg.QueryRow(t.Context(), `SELECT revoked_at IS NOT NULL FROM api_keys WHERE id=$1`, issued.key.ID).Scan(&revoked))
	require.False(t, revoked, "the peer sweep has not retired the row")
	var roles int
	require.NoError(t, b.pg.QueryRow(t.Context(), `SELECT count(*) FROM group_remote_application_roles WHERE remote_application_id=$1`, app.ID).Scan(&roles))
	require.Equal(t, 1, roles, "the peer sweep has not removed the stored application role")
	var queued int
	require.NoError(t, pg.Pool.QueryRow(t.Context(), `SELECT count(*) FROM credential_b_jobs.river_job WHERE kind='authkit_credential_sweep'`).Scan(&queued))
	require.Positive(t, queued)

	_, err = b.RedeemInvitation(t.Context(), iam.UserIdentity(f.user("redeemer").ID), issued.link.Code)
	require.ErrorIs(t, err, errmodel.ErrInvitationRevoked)
	for _, invitation := range []iam.InvitationCreated{issued.invite, issued.plain} {
		ctx := contextWithAccountRegistrationInviteToken(t.Context(), invitation.Code)
		valid, err := b.hasValidAccountRegistrationInvite(ctx, "unused@example.test")
		require.NoError(t, err)
		require.False(t, valid)
		require.ErrorIs(t, b.consumeRegistrationInvite(t.Context(), "unused@example.test", f.user("registrant").ID, invitation.Code), iam.ErrInvitationNotFound)
	}
	allowed, err = b.Can(t.Context(), iam.ApplicationIdentity(app.ID), f.acme, perm)
	require.NoError(t, err)
	require.False(t, allowed)
	allowed, err = verified.Can(t.Context(), verified.bound, perm.String())
	require.NoError(t, err)
	require.False(t, allowed, "previous successful verification cannot preserve revoked application authority")
	allowed, err = b.CanDirect(t.Context(), iam.ApplicationIdentity(app.ID), f.acme, perm)
	require.NoError(t, err)
	require.False(t, allowed)
	permissions, err = b.EffectivePermissions(t.Context(), iam.ApplicationIdentity(app.ID), []iam.GroupRef{f.acme})
	require.NoError(t, err)
	require.Empty(t, permissions)
	listed, err := b.GetRemoteApplication(t.Context(), app.Issuer)
	require.NoError(t, err)
	require.Empty(t, listed.Permissions)
	_, err = b.ResolveAPIKey(t.Context(), control.token)
	require.NoError(t, err, "still-covered peer credentials survive")
	_, err = b.ResolveAPIKey(t.Context(), system.Secret)
	require.NoError(t, err, "system-owned credentials are independent of the demoted user")
}
