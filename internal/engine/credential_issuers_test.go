package engine

import (
	"context"
	"fmt"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/errmodel"
	"github.com/open-rails/authkit/internal/ident"
	"github.com/open-rails/authkit/internal/testdb"
	"github.com/stretchr/testify/require"
)

// credentialFixture is an org persona with API keys, the
// group org/acme owned by founder, and a manager role that issues members.
type credentialFixture struct {
	t       *testing.T
	e       *Engine
	pool    *pgxpool.Pool
	acme    iam.GroupRef
	acmeID  string
	founder iam.Subject
	n       int
}

func credentialConfig(roles RoleConfig) Config {
	cfg := maintenanceConfig()
	cfg.Registration = RegistrationConfig{NativeUserMode: iam.RegistrationModeOpen}
	cfg.Roles = roles
	return cfg
}

func credentialRoles() RoleConfig {
	return RoleConfig{
		Personas: map[string]Persona{"org": {Permissions: []string{"org:catalog:read"}, APIKeys: true}},
		Roles: []Role{
			{Persona: "org", Name: "member", Permissions: []string{"org:catalog:read"}},
			{Persona: "org", Name: "manager", Permissions: []string{"org:members:manage", "org:credentials:manage", "org:catalog:read"}},
			{Persona: "root", Name: "org-admin", Permissions: []string{"org:*"}},
			{Persona: "root", Name: "inviter", Permissions: []string{iam.PermRootUsersInvite.String()}},
			{Persona: "root", Name: "moderator", Permissions: []string{iam.PermRootUsersBan.String()}},
		},
	}
}

func newCredentialFixture(t *testing.T) *credentialFixture {
	t.Helper()
	pg := testdb.ScratchPostgres(t)
	e, err := New(context.Background(), credentialConfig(credentialRoles()), Deps{Postgres: pg.Pool})
	require.NoError(t, err)
	t.Cleanup(e.Close)
	f := &credentialFixture{t: t, e: e, pool: pg.Pool}
	f.founder = f.user("founder")
	f.acmeID, err = seedGroup(t.Context(), e, ident.Persona("org"), f.founder.ID)
	require.NoError(t, err)
	f.acme = iam.GroupByID(f.acmeID)
	return f
}

// role is the org role name.
func (f *credentialFixture) role(name string) iam.Role { return ident.Role(ident.Persona("org"), name) }

func (f *credentialFixture) user(prefix string) iam.Subject {
	f.n++
	u, err := f.e.createUser(f.t.Context(), fmt.Sprintf("%s%d@credentials.test", prefix, f.n), fmt.Sprintf("%s%d", prefix, f.n))
	require.NoError(f.t, err)
	return iam.UserSubject(u.ID)
}

// issued is one of each credential a creator can issue in acme: an API key, an
// invite link, a role-carrying and a plain registration invite.
type issued struct {
	key                     iam.APIKey
	token                   string
	link                    iam.InviteLinkCreated
	invite, plain           iam.AccountInviteCreated
	inviteEmail, plainEmail string
}

func (f *credentialFixture) issue(t *testing.T, creator iam.Subject, keyRole string, plain bool) issued {
	t.Helper()
	ctx := t.Context()
	a := iam.UserActor(creator.ID)
	var out issued
	var err error
	out.key, out.token, err = f.e.MintAPIKey(ctx, a, f.acme, iam.NewAPIKey{Name: "key", Role: f.role(keyRole)})
	require.NoError(t, err)
	out.link, err = f.e.CreateInviteLink(ctx, a, f.acme, iam.NewInviteLink{Role: f.role("member")})
	require.NoError(t, err)
	f.n++
	out.inviteEmail = fmt.Sprintf("invitee%d@credentials.test", f.n)
	out.invite, err = f.e.CreateAccountInvite(ctx, a, iam.NewAccountInvite{Email: out.inviteEmail, Group: f.acme, Role: f.role("member")})
	require.NoError(t, err)
	if plain {
		out.plainEmail = fmt.Sprintf("plain%d@credentials.test", f.n)
		out.plain, err = f.e.CreateAccountInvite(ctx, a, iam.NewAccountInvite{Email: out.plainEmail})
		require.NoError(t, err)
	}
	return out
}

// requireDead asserts none of c works any more.
func (f *credentialFixture) requireDead(t *testing.T, c issued) {
	t.Helper()
	ctx := t.Context()
	_, err := f.e.ResolveAPIKey(ctx, c.token)
	require.ErrorIs(t, err, iam.ErrAPIKeyRevoked, "API key")
	_, err = f.e.RedeemInviteLink(ctx, iam.UserActor(f.user("redeemer").ID), c.link.Code)
	require.ErrorIs(t, err, errmodel.ErrInviteLinkRevoked, "invite link")
	require.ErrorIs(t, f.e.consumeRegistrationInvite(ctx, c.inviteEmail, f.user("registrant").ID, c.invite.Code), errmodel.ErrAccountRegistrationInviteNotFound, "registration invite")
	if c.plain.Code != "" {
		require.ErrorIs(t, f.e.consumeRegistrationInvite(ctx, c.plainEmail, f.user("registrant").ID, c.plain.Code), errmodel.ErrAccountRegistrationInviteNotFound, "plain registration invite")
	}
}

// requireCredentialsCovered is invariant #2: every live credential with a
// creator is one that creator could issue right now (live, holding the
// capability, covering the role in its group plus root).
func requireCredentialsCovered(t *testing.T, e *Engine) {
	t.Helper()
	ctx := t.Context()
	st := e.groupStore()
	rows, err := st.q.Query(ctx, `
SELECT 'api_keys', k.id::text, g.id::text, g.persona, k.role, k.created_by::text FROM api_keys k JOIN permission_groups g ON g.id=k.permission_group_id
 WHERE k.revoked_at IS NULL AND (k.expires_at IS NULL OR k.expires_at>now()) AND k.created_by IS NOT NULL AND g.deleted_at IS NULL
UNION ALL
SELECT 'group_invite_links', l.id::text, g.id::text, g.persona, l.role, l.invited_by::text FROM group_invite_links l JOIN permission_groups g ON g.id=l.permission_group_id
 WHERE l.revoked_at IS NULL AND l.redeemed_at IS NULL AND (l.expires_at IS NULL OR l.expires_at>now()) AND l.invited_by IS NOT NULL AND g.deleted_at IS NULL
UNION ALL
SELECT 'account_registration_invites', a.id::text, g.id::text, g.persona, COALESCE(a.role,''), a.invited_by::text FROM account_registration_invites a
  JOIN permission_groups g ON g.id=a.permission_group_id OR (a.permission_group_id IS NULL AND g.persona='root')
 WHERE a.revoked_at IS NULL AND a.consumed_at IS NULL AND a.expires_at>now() AND a.invited_by IS NOT NULL AND g.deleted_at IS NULL`)
	require.NoError(t, err)
	type credential struct {
		table, id, creator string
		g                  groupTarget
		role               iam.Role
	}
	var creds []credential
	for rows.Next() {
		var c credential
		var persona, role string
		require.NoError(t, rows.Scan(&c.table, &c.id, &c.g.ID, &persona, &role, &c.creator))
		c.g.Persona = ident.Persona(persona)
		c.role = ident.Role(c.g.Persona, role)
		creds = append(creds, c)
	}
	require.NoError(t, rows.Err())
	for _, c := range creds {
		capability := iam.PermMembersManage(c.g.Persona)
		switch {
		case c.table == "api_keys":
			capability = iam.PermCredentialsManage(c.g.Persona)
		case c.role.IsZero():
			capability = iam.PermRootUsersInvite
		}
		require.NoError(t, e.creatorCovers(ctx, st, c.creator, c.g, capability, c.role), "%s %s outlived its issuer %s", c.table, c.id, c.creator)
	}
}

// Invariant #2: after every authority change, each live key, link and
// registration invite still has a creator that could issue it now. The
// subtests on their own fixture leave dead creators' rows behind on purpose.
func TestNoCredentialOutlivesItsIssuer(t *testing.T) {
	f := newCredentialFixture(t)
	ctx := t.Context()
	owner := iam.UserActor(f.founder.ID)
	control := f.issue(t, f.founder, "manager", false)
	for _, tc := range []struct {
		name        string
		grant, lose func(t *testing.T, creator iam.Subject)
	}{
		{"demoted", func(t *testing.T, c iam.Subject) { grantRole(t, f.e, f.acme, c, "manager") }, func(t *testing.T, c iam.Subject) {
			require.NoError(t, assignRole(ctx, f.e, owner, f.acme, c, "member"))
		}},
		{"removed", func(t *testing.T, c iam.Subject) { grantRole(t, f.e, f.acme, c, "manager") }, func(t *testing.T, c iam.Subject) {
			require.NoError(t, removeMember(ctx, f.e, owner, f.acme, c))
		}},
		{"root role lost", func(t *testing.T, c iam.Subject) { grantRole(t, f.e, iam.RootGroup(), c, "org-admin") }, func(t *testing.T, c iam.Subject) {
			require.NoError(t, unassignRole(ctx, f.e, iam.SystemActor(), iam.RootGroup(), c, "org-admin"))
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			creator := f.user("creator")
			tc.grant(t, creator)
			c := f.issue(t, creator, "member", false)
			tc.lose(t, creator)
			requireCredentialsCovered(t, f.e)
			f.requireDead(t, c)
			_, err := f.e.ResolveAPIKey(ctx, control.token)
			require.NoError(t, err, "the owner's credentials survive")
		})
	}
	t.Run("root invite permission lost", func(t *testing.T) {
		creator := f.user("inviter")
		grantRole(t, f.e, iam.RootGroup(), creator, "inviter")
		plain, err := f.e.CreateAccountInvite(ctx, iam.UserActor(creator.ID), iam.NewAccountInvite{Email: "lost@credentials.test"})
		require.NoError(t, err)
		require.NoError(t, unassignRole(ctx, f.e, iam.SystemActor(), iam.RootGroup(), creator, "inviter"))
		requireCredentialsCovered(t, f.e)
		require.ErrorIs(t, f.e.consumeRegistrationInvite(ctx, "lost@credentials.test", f.user("registrant").ID, plain.Code), errmodel.ErrAccountRegistrationInviteNotFound)
	})

	// H1: a banned, deleted or reserved creator's credentials fail at use
	// time, even on a path that changed the account without running the sweep.
	t.Run("refused before any sweep", func(t *testing.T) {
		f := newCredentialFixture(t)
		for _, end := range []struct{ name, sql string }{
			{"banned", `UPDATE users SET banned_at=now(), ban_reason='spam' WHERE id=$1::uuid`},
			{"deleted", `UPDATE users SET deleted_at=now() WHERE id=$1::uuid`},
			{"reserved", `UPDATE users SET metadata=COALESCE(metadata,'{}'::jsonb)||'{"reserved":true}'::jsonb WHERE id=$1::uuid`},
		} {
			t.Run(end.name, func(t *testing.T) {
				creator := f.user(end.name)
				grantRole(t, f.e, f.acme, creator, "manager")
				grantRole(t, f.e, iam.RootGroup(), creator, "inviter")
				c := f.issue(t, creator, "manager", true)
				require.NoError(t, assignRole(ctx, f.e, iam.APIKeyActor(c.key.ID), f.acme, f.user("control"), "member"), "a live creator's key acts")
				_, err := f.e.pg.Exec(ctx, end.sql, creator.ID)
				require.NoError(t, err)
				f.requireDead(t, c)
				require.ErrorIs(t, assignRole(ctx, f.e, iam.APIKeyActor(c.key.ID), f.acme, f.user("target"), "member"), iam.ErrInsufficientAuthority)
			})
		}
	})

	// H1: purging the creator deletes its keys and links, so no live key is
	// ever left creator-less; system-issued keys are the only ones without a
	// creator.
	t.Run("purged", func(t *testing.T) {
		f := newCredentialFixture(t)
		creator := f.user("purged")
		grantRole(t, f.e, f.acme, creator, "manager")
		c := f.issue(t, creator, "member", false)
		_, opToken, err := f.e.MintAPIKey(ctx, iam.SystemActor(), f.acme, iam.NewAPIKey{Name: "system", Role: f.role("member")})
		require.NoError(t, err)
		generation := prepareExpiredDeletion(t, f.e, creator.ID)
		f.requireDead(t, c)
		require.NoError(t, f.e.finalizeAccountDeletion(ctx, generation, true))
		var rows int
		require.NoError(t, f.e.pg.QueryRow(ctx, `SELECT (SELECT count(*) FROM api_keys WHERE id=$1::uuid)+(SELECT count(*) FROM group_invite_links WHERE id=$2::uuid)`, c.key.ID, c.link.ID).Scan(&rows))
		require.Zero(t, rows, "the purged creator's credentials remain")
		_, err = f.e.ResolveAPIKey(ctx, c.token)
		require.ErrorIs(t, err, iam.ErrAPIKeyInvalid)
		_, err = f.e.ResolveAPIKey(ctx, opToken)
		require.NoError(t, err)
		var creatorless, deadCreator int
		require.NoError(t, f.e.pg.QueryRow(ctx, `SELECT count(*) FILTER (WHERE created_by IS NULL), count(*) FILTER (WHERE NOT (k.created_by IS NULL OR EXISTS(SELECT 1 FROM usable_users WHERE id=k.created_by)))
 FROM api_keys k WHERE revoked_at IS NULL`).Scan(&creatorless, &deadCreator))
		require.Equal(t, 1, creatorless, "only the system's key has no creator")
		require.Zero(t, deadCreator)
		requireCredentialsCovered(t, f.e)
	})

	// L9: a bootstrap that demotes a root admin revokes what they issued.
	t.Run("bootstrap demotion", func(t *testing.T) {
		f := newCredentialFixture(t)
		apply := func(role string) {
			_, err := f.e.ApplyBootstrapManifest(ctx, iam.BootstrapManifest{Users: []iam.BootstrapManifestUser{
				{Email: "ops@credentials.test", Username: "siteops", EmailVerified: true, RootRole: mustRole("root:" + role)},
			}}, iam.BootstrapOptions{})
			require.NoError(t, err)
		}
		apply("org-admin")
		var ops string
		require.NoError(t, f.e.pg.QueryRow(ctx, `SELECT id::text FROM users WHERE email='ops@credentials.test'`).Scan(&ops))
		c := f.issue(t, iam.UserSubject(ops), "manager", false)
		apply("moderator")
		requireCredentialsCovered(t, f.e)
		f.requireDead(t, c)
		keys, err := f.e.APIKeys(ctx, f.acme, iam.PageRequest{})
		require.NoError(t, err)
		require.NotNil(t, keys.Items[0].RevokedAt, "revoked in storage, not only refused")
	})
}

// L9: New re-checks every credential when the role catalog changed.
func TestRoleCatalogChangesAtBoot(t *testing.T) {
	f := newCredentialFixture(t)
	ctx := t.Context()
	manager := f.user("manager")
	grantRole(t, f.e, f.acme, manager, "manager")
	c := f.issue(t, manager, "member", false)
	control := f.issue(t, f.founder, "manager", false)
	boot := func(roles RoleConfig) (*Engine, error) {
		e, err := New(context.Background(), credentialConfig(roles), Deps{Postgres: f.pool})
		if err == nil {
			t.Cleanup(e.Close)
		}
		return e, err
	}
	fingerprint := func() (fp string, swept string) {
		require.NoError(t, f.e.pg.QueryRow(ctx, `SELECT fingerprint, swept_at::text FROM role_catalog_state`).Scan(&fp, &swept))
		return fp, swept
	}
	fp, swept := fingerprint()
	require.Equal(t, f.e.roleCatalogFingerprint(), fp)
	_, err := boot(credentialRoles())
	require.NoError(t, err)
	_, again := fingerprint()
	require.Equal(t, swept, again, "an unchanged catalog is not re-swept")

	narrowed := credentialRoles()
	narrowed.Roles[1].Permissions = []string{"org:catalog:read"} // manager issues nothing any more
	e, err := boot(narrowed)
	require.NoError(t, err)
	fp, _ = fingerprint()
	require.Equal(t, e.roleCatalogFingerprint(), fp)
	requireCredentialsCovered(t, e)
	f.requireDead(t, c)
	_, err = e.ResolveAPIKey(ctx, control.token)
	require.NoError(t, err, "the owner's credentials survive")
}

func (s *Engine) consumeRegistrationInvite(ctx context.Context, email, userID, token string) error {
	return s.consumeAccountRegistrationInvite(contextWithAccountRegistrationInviteToken(ctx, token), email, userID)
}
