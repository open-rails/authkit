package engine

import (
	"fmt"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/authflow"
	"github.com/open-rails/authkit/internal/errmodel"
	"github.com/open-rails/authkit/internal/testdb"
	"github.com/stretchr/testify/require"
)

// credentialFixture is an org persona with API keys and custom roles, the
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
		Personas: map[string]Persona{"org": {Permissions: []string{"org:catalog:read"}, APIKeys: true, CustomRoles: true}},
		Roles: []Role{
			{Persona: "org", Name: "member", Permissions: []string{"org:catalog:read"}},
			{Persona: "org", Name: "manager", Permissions: []string{"org:members:manage", "org:credentials:manage", "org:catalog:read"}},
			{Persona: iam.RootPersona, Name: "org-admin", Permissions: []string{"org:*"}},
			{Persona: iam.RootPersona, Name: "inviter", Permissions: []string{iam.PermRootUsersInvite}},
			{Persona: iam.RootPersona, Name: "moderator", Permissions: []string{iam.PermRootUsersBan}},
		},
	}
}

func newCredentialFixture(t *testing.T) *credentialFixture {
	t.Helper()
	pg := testdb.ScratchPostgres(t)
	e, err := New(credentialConfig(credentialRoles()), Deps{Postgres: pg.Pool})
	require.NoError(t, err)
	t.Cleanup(e.Close)
	f := &credentialFixture{t: t, e: e, pool: pg.Pool, acme: iam.GroupBySlug("org", "acme")}
	f.founder = f.user("founder")
	f.acmeID, err = e.CreatePermissionGroup(t.Context(), iam.CreatePermissionGroupRequest{Persona: "org", InstanceSlug: "acme", OwnerSubjectID: f.founder.ID})
	require.NoError(t, err)
	return f
}

func (f *credentialFixture) user(prefix string) iam.Subject {
	f.n++
	u, err := f.e.CreateUser(f.t.Context(), fmt.Sprintf("%s%d@credentials.test", prefix, f.n), fmt.Sprintf("%s%d", prefix, f.n))
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

func (f *credentialFixture) issue(t *testing.T, creator iam.Subject, keyRole iam.Role, plain bool) issued {
	t.Helper()
	ctx := t.Context()
	a := iam.UserActor(creator.ID)
	var out issued
	var err error
	out.key, out.token, err = f.e.MintAPIKey(ctx, a, f.acme, iam.NewAPIKey{Name: "key", Role: keyRole})
	require.NoError(t, err)
	out.link, err = f.e.CreateInviteLink(ctx, a, f.acme, iam.NewInviteLink{Role: "member"})
	require.NoError(t, err)
	f.n++
	out.inviteEmail = fmt.Sprintf("invitee%d@credentials.test", f.n)
	out.invite, err = f.e.CreateAccountInvite(ctx, a, iam.NewAccountInvite{Email: out.inviteEmail, Group: f.acme, Role: "member"})
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
	require.ErrorIs(t, err, iam.ErrAccessTokenRevoked, "API key")
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
		require.NoError(t, rows.Scan(&c.table, &c.id, &c.g.ID, &c.g.Persona, &c.role, &c.creator))
		creds = append(creds, c)
	}
	require.NoError(t, rows.Err())
	for _, c := range creds {
		capability := iam.PermMembersManage(c.g.Persona)
		switch {
		case c.table == "api_keys":
			capability = iam.PermCredentialsManage(c.g.Persona)
		case c.role == "":
			capability = iam.PermRootUsersInvite
		}
		require.NoError(t, e.creatorCovers(ctx, st, c.creator, c.g, capability, c.role), "%s %s outlived its issuer %s", c.table, c.id, c.creator)
	}
}

func TestCredentialIssuance(t *testing.T) {
	f := newCredentialFixture(t)
	ctx := t.Context()
	manager, member, inviter := f.user("manager"), f.user("member"), f.user("inviter")
	grantRole(t, f.e, f.acme, manager, "manager")
	grantRole(t, f.e, f.acme, member, "member")
	grantRole(t, f.e, iam.RootGroup(), inviter, "inviter")
	mgr := iam.UserActor(manager.ID)

	// A user issues what it covers and is recorded as the creator.
	key, token, err := f.e.MintAPIKey(ctx, mgr, f.acme, iam.NewAPIKey{Name: " ci ", Role: "Member"})
	require.NoError(t, err)
	require.Equal(t, iam.APIKey{ID: key.ID, LookupID: key.LookupID, Name: "ci", Role: "member", Permissions: []string{"org:catalog:read"}, CreatedBy: manager.ID, CreatedAt: key.CreatedAt}, key)
	principal, err := f.e.ResolveAPIKey(ctx, token)
	require.NoError(t, err)
	require.Equal(t, key.ID, principal.ID)
	require.Equal(t, key.LookupID, principal.LookupID)
	require.Equal(t, iam.GroupInstance{ID: f.acmeID, Persona: "org", InstanceSlug: "acme", DisplayName: principal.Group.DisplayName}, principal.Group)
	require.Equal(t, "https://maintenance.test", principal.Issuer)
	require.Equal(t, iam.Role("member"), principal.Role)
	require.Equal(t, []string{"org:catalog:read"}, principal.Permissions)
	require.Nil(t, principal.ExpiresAt)
	link, err := f.e.CreateInviteLink(ctx, mgr, f.acme, iam.NewInviteLink{Role: "member"})
	require.NoError(t, err)
	require.NotEmpty(t, link.Code)

	// No escalation, and no capability means no issuance.
	_, _, err = f.e.MintAPIKey(ctx, mgr, f.acme, iam.NewAPIKey{Name: "owner", Role: iam.OwnerRole})
	require.ErrorIs(t, err, iam.ErrRoleAssignmentEscalation)
	_, err = f.e.CreateInviteLink(ctx, mgr, f.acme, iam.NewInviteLink{Role: iam.OwnerRole})
	require.ErrorIs(t, err, iam.ErrRoleAssignmentEscalation)
	_, _, err = f.e.MintAPIKey(ctx, iam.UserActor(member.ID), f.acme, iam.NewAPIKey{Name: "member", Role: "member"})
	require.ErrorIs(t, err, iam.ErrInsufficientRoleAuthority)
	_, _, err = f.e.MintAPIKey(ctx, iam.OperatorActor(), f.acme, iam.NewAPIKey{Name: "unknown", Role: "nobody"})
	require.ErrorIs(t, err, errmodel.ErrUnknownRole, "the operator skips authority, never role validity")

	// Machine actors never issue credentials, whatever authority they hold.
	managerKey, _, err := f.e.MintAPIKey(ctx, iam.UserActor(f.founder.ID), f.acme, iam.NewAPIKey{Name: "manager-key", Role: "manager"})
	require.NoError(t, err)
	for name, a := range map[string]iam.Actor{
		"zero":               {},
		"api_key":            iam.APIKeyActor(managerKey.ID),
		"remote_application": iam.RemoteApplicationActor(uuid.NewString()),
		"delegated":          iam.DelegatedActor(iam.DelegatedGrant{Issuer: "https://maintenance.test", Subject: manager.ID, Permissions: []iam.Perm{"org:*"}}),
	} {
		_, _, err := f.e.MintAPIKey(ctx, a, f.acme, iam.NewAPIKey{Name: name, Role: "member"})
		require.ErrorIs(t, err, iam.ErrInsufficientRoleAuthority, name)
		_, err = f.e.CreateInviteLink(ctx, a, f.acme, iam.NewInviteLink{Role: "member"})
		require.ErrorIs(t, err, iam.ErrInsufficientRoleAuthority, name)
		_, err = f.e.CreateAccountInvite(ctx, a, iam.NewAccountInvite{Email: name + "@machine.test", Group: f.acme, Role: "member"})
		require.ErrorIs(t, err, iam.ErrInsufficientRoleAuthority, name)
	}

	// Revoking needs the authority to issue, from any actor kind.
	ok, err := f.e.RevokeAPIKey(ctx, iam.UserActor(member.ID), f.acme, key.ID)
	require.ErrorIs(t, err, iam.ErrInsufficientRoleAuthority)
	require.False(t, ok)
	ok, err = f.e.RevokeAPIKey(ctx, iam.APIKeyActor(managerKey.ID), f.acme, key.ID)
	require.NoError(t, err)
	require.True(t, ok)
	_, err = f.e.ResolveAPIKey(ctx, token)
	require.ErrorIs(t, err, iam.ErrAccessTokenRevoked)
	ok, err = f.e.RevokeAPIKey(ctx, mgr, f.acme, key.ID)
	require.NoError(t, err)
	require.False(t, ok, "no live key")
	require.ErrorIs(t, f.e.RevokeInviteLink(ctx, iam.UserActor(member.ID), f.acme, link.ID), iam.ErrInsufficientRoleAuthority)
	require.NoError(t, f.e.RevokeInviteLink(ctx, mgr, f.acme, link.ID))
	require.ErrorIs(t, f.e.RevokeInviteLink(ctx, mgr, f.acme, link.ID), iam.ErrInviteLinkNotFound)

	// Registration invites: plain needs root:users:invite, a role-carrying one
	// the group's members:manage and coverage of the role.
	_, err = f.e.CreateAccountInvite(ctx, mgr, iam.NewAccountInvite{Email: "plain@credentials.test"})
	require.ErrorIs(t, err, iam.ErrInsufficientRoleAuthority)
	_, err = f.e.CreateAccountInvite(ctx, iam.UserActor(inviter.ID), iam.NewAccountInvite{Email: "plain@credentials.test"})
	require.NoError(t, err)
	_, err = f.e.CreateAccountInvite(ctx, iam.UserActor(inviter.ID), iam.NewAccountInvite{Email: "join@credentials.test", Group: f.acme, Role: "member"})
	require.ErrorIs(t, err, iam.ErrInsufficientRoleAuthority)
	_, err = f.e.CreateAccountInvite(ctx, mgr, iam.NewAccountInvite{Email: "join@credentials.test", Group: f.acme, Role: iam.OwnerRole})
	require.ErrorIs(t, err, iam.ErrRoleAssignmentEscalation)
	_, err = f.e.CreateAccountInvite(ctx, mgr, iam.NewAccountInvite{Email: "join@credentials.test", Role: "member"})
	require.ErrorIs(t, err, errmodel.ErrInvalidInvite, "a role needs a group")

	// The operator issues with no creator, and nothing sweeps its credentials.
	opKey, opToken, err := f.e.MintAPIKey(ctx, iam.OperatorActor(), f.acme, iam.NewAPIKey{Name: "operator", Role: iam.OwnerRole})
	require.NoError(t, err)
	require.Empty(t, opKey.CreatedBy)
	opLink, err := f.e.CreateInviteLink(ctx, iam.OperatorActor(), f.acme, iam.NewInviteLink{Role: iam.OwnerRole})
	require.NoError(t, err)
	opInvite, err := f.e.CreateAccountInvite(ctx, iam.OperatorActor(), iam.NewAccountInvite{Email: "operator@credentials.test"})
	require.NoError(t, err)
	require.NoError(t, f.e.withAuthorityMutation(ctx, func(st *permissionGroupStore) error {
		return f.e.revokeCredentialsOf(ctx, st, manager.ID)
	}))
	require.NoError(t, f.e.withAuthorityMutation(ctx, func(st *permissionGroupStore) error {
		root, err := f.e.rootGroup(ctx, st)
		if err != nil {
			return err
		}
		return f.e.revokeUncoveredCredentials(ctx, st, authorityTouch{groupID: root})
	}))
	_, err = f.e.ResolveAPIKey(ctx, opToken)
	require.NoError(t, err)
	links, err := f.e.InviteLinks(ctx, f.acme, iam.PageRequest{})
	require.NoError(t, err)
	require.Equal(t, opLink.ID, links.Items[0].ID)
	require.Empty(t, links.Items[0].InvitedBy)
	require.Nil(t, links.Items[0].RevokedAt)
	var opInviter *string
	require.NoError(t, f.e.pg.QueryRow(ctx, `SELECT invited_by::text FROM account_registration_invites WHERE id=$1::uuid AND revoked_at IS NULL`, opInvite.ID).Scan(&opInviter))
	require.Nil(t, opInviter)

	// Tokens: anything but an exact live key is refused.
	for _, bad := range []string{"", "st_", "st_" + opKey.LookupID, "st_" + opKey.LookupID + "_wrongsecret", "x" + opToken, opToken + "x"} {
		_, err := f.e.ResolveAPIKey(ctx, bad)
		require.ErrorIs(t, err, iam.ErrInvalidAccessToken, bad)
	}
	_, err = f.e.pg.Exec(ctx, `UPDATE api_keys SET expires_at=now()-interval '1 minute' WHERE id=$1::uuid`, opKey.ID)
	require.NoError(t, err)
	_, err = f.e.ResolveAPIKey(ctx, opToken)
	require.ErrorIs(t, err, iam.ErrAccessTokenExpired)
}

func TestCredentialListsPage(t *testing.T) {
	f := newCredentialFixture(t)
	ctx := t.Context()
	var keys, links []string
	for i := range 3 {
		k, _, err := f.e.MintAPIKey(ctx, iam.OperatorActor(), f.acme, iam.NewAPIKey{Name: fmt.Sprintf("key-%d", i), Role: "member"})
		require.NoError(t, err)
		keys = append([]string{k.ID}, keys...)
		l, err := f.e.CreateInviteLink(ctx, iam.OperatorActor(), f.acme, iam.NewInviteLink{Role: "member"})
		require.NoError(t, err)
		links = append([]string{l.ID}, links...)
	}
	first, err := f.e.APIKeys(ctx, f.acme, iam.PageRequest{Limit: 2})
	require.NoError(t, err)
	require.Equal(t, keys[:2], []string{first.Items[0].ID, first.Items[1].ID}, "newest first")
	require.Equal(t, []string{"org:catalog:read"}, first.Items[0].Permissions)
	require.NotEmpty(t, first.Next)
	rest, err := f.e.APIKeys(ctx, f.acme, iam.PageRequest{Limit: 2, Cursor: first.Next})
	require.NoError(t, err)
	require.Len(t, rest.Items, 1)
	require.Equal(t, keys[2], rest.Items[0].ID)
	require.Empty(t, rest.Next)
	all, err := f.e.InviteLinks(ctx, f.acme, iam.PageRequest{})
	require.NoError(t, err)
	require.Len(t, all.Items, 3)
	require.Equal(t, links[0], all.Items[0].ID)
	require.Empty(t, all.Next)
	page, err := f.e.InviteLinks(ctx, f.acme, iam.PageRequest{Limit: 1, Cursor: links[0]})
	require.NoError(t, err)
	require.Equal(t, links[1], page.Items[0].ID)
	_, err = f.e.APIKeys(ctx, f.acme, iam.PageRequest{Cursor: "not-a-cursor"})
	require.ErrorIs(t, err, errmodel.E(errmodel.CodeInvalidRequest))
	_, err = f.e.APIKeys(ctx, iam.GroupBySlug("org", "missing"), iam.PageRequest{})
	require.ErrorIs(t, err, iam.ErrGroupNotFound)
}

// H1: a banned, deleted or reserved creator's credentials fail at use time,
// even on a path that changed the account without running the sweep.
func TestCredentialsOfDeadCreatorsAreRefused(t *testing.T) {
	f := newCredentialFixture(t)
	ctx := t.Context()
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
			require.ErrorIs(t, assignRole(ctx, f.e, iam.APIKeyActor(c.key.ID), f.acme, f.user("target"), "member"), iam.ErrInsufficientRoleAuthority)
		})
	}
}

// H1: purging the creator deletes its keys and links, so no live key is ever
// left creator-less; operator-issued keys are the only ones without a creator.
func TestPurgeDeletesTheCreatorsCredentials(t *testing.T) {
	f := newCredentialFixture(t)
	ctx := t.Context()
	creator := f.user("purged")
	grantRole(t, f.e, f.acme, creator, "manager")
	c := f.issue(t, creator, "member", false)
	_, opToken, err := f.e.MintAPIKey(ctx, iam.OperatorActor(), f.acme, iam.NewAPIKey{Name: "operator", Role: "member"})
	require.NoError(t, err)
	generation := prepareExpiredDeletion(t, f.e, creator.ID)
	f.requireDead(t, c)
	require.NoError(t, f.e.finalizeAccountDeletion(ctx, generation, true))
	var rows int
	require.NoError(t, f.e.pg.QueryRow(ctx, `SELECT (SELECT count(*) FROM api_keys WHERE id=$1::uuid)+(SELECT count(*) FROM group_invite_links WHERE id=$2::uuid)`, c.key.ID, c.link.ID).Scan(&rows))
	require.Zero(t, rows, "the purged creator's credentials remain")
	_, err = f.e.ResolveAPIKey(ctx, c.token)
	require.ErrorIs(t, err, iam.ErrInvalidAccessToken)
	_, err = f.e.ResolveAPIKey(ctx, opToken)
	require.NoError(t, err)
	var creatorless, deadCreator int
	require.NoError(t, f.e.pg.QueryRow(ctx, `SELECT count(*) FILTER (WHERE created_by IS NULL), count(*) FILTER (WHERE NOT `+issuerLive("k.created_by")+`)
 FROM api_keys k WHERE revoked_at IS NULL`).Scan(&creatorless, &deadCreator))
	require.Equal(t, 1, creatorless, "only the operator's key has no creator")
	require.Zero(t, deadCreator)
	requireCredentialsCovered(t, f.e)
}

// Invariant #2: after every authority change, each live key, link and
// registration invite still has a creator that could issue it now.
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
			revokeRole(t, f.e, iam.RootGroup(), c, "org-admin")
		}},
		{"custom role narrowed", func(t *testing.T, c iam.Subject) {
			f.defineCustomRole(t, "keeper", "org:members:manage", "org:credentials:manage", "org:catalog:read")
			grantRole(t, f.e, f.acme, c, "keeper")
		}, func(t *testing.T, _ iam.Subject) {
			f.defineCustomRole(t, "keeper", "org:catalog:read")
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
		revokeRole(t, f.e, iam.RootGroup(), creator, "inviter")
		requireCredentialsCovered(t, f.e)
		require.ErrorIs(t, f.e.consumeRegistrationInvite(ctx, "lost@credentials.test", f.user("registrant").ID, plain.Code), errmodel.ErrAccountRegistrationInviteNotFound)
	})
}

func (f *credentialFixture) defineCustomRole(t *testing.T, role iam.Role, perms ...string) {
	t.Helper()
	require.NoError(t, f.e.withGroupMutation(t.Context(), f.acme, func(st *permissionGroupStore, g groupTarget) error {
		return st.UpsertCustomRole(t.Context(), g.ID, authflow.CustomRoleDef{Role: role, Permissions: perms})
	}))
}

// L9: a bootstrap that demotes a root admin revokes what they issued.
func TestBootstrapDemotionRevokesCredentials(t *testing.T) {
	f := newCredentialFixture(t)
	ctx := t.Context()
	apply := func(role string) {
		_, err := f.e.OperatorApplyBootstrapManifest(ctx, iam.BootstrapManifest{Users: []iam.BootstrapManifestUser{
			{Email: "ops@credentials.test", Username: "siteops", EmailVerified: true, RootRole: role},
		}}, iam.BootstrapReconcileOptions{})
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
}

// L9: New re-checks every credential when the role catalog changed, and
// refuses a catalog role that shadows a stored custom role.
func TestRoleCatalogChangesAtBoot(t *testing.T) {
	f := newCredentialFixture(t)
	ctx := t.Context()
	manager := f.user("manager")
	grantRole(t, f.e, f.acme, manager, "manager")
	c := f.issue(t, manager, "member", false)
	control := f.issue(t, f.founder, "manager", false)
	boot := func(roles RoleConfig) (*Engine, error) {
		e, err := New(credentialConfig(roles), Deps{Postgres: f.pool})
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
	require.Equal(t, roleCatalogFingerprint(f.e.groupSchemaOrDefault()), fp)
	_, err := boot(credentialRoles())
	require.NoError(t, err)
	_, again := fingerprint()
	require.Equal(t, swept, again, "an unchanged catalog is not re-swept")

	narrowed := credentialRoles()
	narrowed.Roles[1].Permissions = []string{"org:catalog:read"} // manager issues nothing any more
	e, err := boot(narrowed)
	require.NoError(t, err)
	fp, _ = fingerprint()
	require.Equal(t, roleCatalogFingerprint(e.groupSchemaOrDefault()), fp)
	requireCredentialsCovered(t, e)
	f.requireDead(t, c)
	_, err = e.ResolveAPIKey(ctx, control.token)
	require.NoError(t, err, "the owner's credentials survive")

	f.defineCustomRole(t, "auditor", "org:catalog:read")
	shadowing := credentialRoles()
	shadowing.Roles = append(shadowing.Roles, Role{Persona: "org", Name: "auditor", Permissions: []string{"org:*"}})
	_, err = boot(shadowing)
	require.ErrorContains(t, err, "org/auditor")
}
