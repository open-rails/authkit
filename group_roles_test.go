package authkit

import (
	"errors"
	"fmt"
	"testing"

	"github.com/google/uuid"
	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/testdb"
	"github.com/stretchr/testify/require"
)

func TestGroupRoleOperations(t *testing.T) {
	pg := testdb.ScratchPostgres(t)
	roles := RoleConfig{
		Personas: map[string]Persona{"root": {Permissions: []string{"root:posts:edit"}}},
		Roles: []Role{
			{Persona: iam.RootPersona, Name: "editor", Permissions: []string{"root:posts:edit"}},
			{Persona: iam.RootPersona, Name: "admin", Permissions: []string{string(iam.PermMembersManage(iam.RootPersona)), "root:posts:edit"}},
		},
	}
	engine := mustNewWithKeys(t, Config{Token: TokenConfig{Issuer: "https://group-roles.test"},
		TwoFactor: TwoFactorConfig{Mode: iam.TwoFactorDisabled}, Roles: roles}, keyset{}, Deps{Postgres: pg.Pool})
	ctx := t.Context()
	newUser := func(name string) iam.Subject {
		u, err := engine.CreateUser(ctx, name+"@example.test", name)
		require.NoError(t, err)
		return iam.UserSubject(u.ID)
	}
	root, stranger := iam.RootGroup(), iam.UserSubject(uuid.NewString())
	owner, admin, editor, other := newUser("owner"), newUser("admin"), newUser("editor"), newUser("other")

	// The operator skips authority rules, never invariants.
	grantRole(t, engine, root, owner, iam.OwnerRole)
	require.ErrorIs(t, unassignRole(ctx, engine, iam.OperatorActor(), root, owner, iam.OwnerRole), iam.ErrCannotRemoveLastAdminRole)
	require.ErrorIs(t, assignRole(ctx, engine, iam.OperatorActor(), root, owner, "editor"), iam.ErrCannotRemoveLastAdminRole)
	require.ErrorIs(t, assignRole(ctx, engine, iam.OperatorActor(), root, stranger, "editor"), iam.ErrUserNotFound)
	_, err := engine.AssignGroupRoles(ctx, iam.OperatorActor(), root, []iam.Subject{editor}, "unknown")
	require.ErrorIs(t, err, iam.ErrRoleNotAssignable)
	_, err = engine.AssignGroupRoles(ctx, iam.Actor{}, root, []iam.Subject{editor}, "editor")
	require.ErrorIs(t, err, iam.ErrInsufficientRoleAuthority, "the zero actor is refused")

	// root:members:manage lets a bounded admin grant what it covers, never more.
	grantRole(t, engine, root, admin, "admin")
	res, err := engine.AssignGroupRoles(ctx, iam.UserActor(admin.ID), root, []iam.Subject{editor, other, stranger}, "editor")
	require.NoError(t, err)
	require.NoError(t, res[0].Err)
	require.NoError(t, res[1].Err)
	require.ErrorIs(t, res[2].Err, iam.ErrUserNotFound, "items fail independently")
	require.ErrorIs(t, assignRole(ctx, engine, iam.UserActor(admin.ID), root, other, iam.OwnerRole), iam.ErrRoleAssignmentEscalation)
	require.ErrorIs(t, removeMember(ctx, engine, iam.UserActor(admin.ID), root, owner), iam.ErrRoleAssignmentEscalation)
	require.ErrorIs(t, unassignRole(ctx, engine, iam.UserActor(editor.ID), root, other, "editor"), iam.ErrInsufficientRoleAuthority)
	require.ErrorIs(t, assignRole(ctx, engine, iam.UserActor(owner.ID).Within("root:posts:*"), root, other, "admin"), iam.ErrInsufficientRoleAuthority, "a ceiling narrows even the owner")

	held, err := engine.GroupRoles(ctx, root, []iam.Subject{owner, admin, editor, other, stranger})
	require.NoError(t, err)
	require.Equal(t, map[iam.Subject]iam.Role{owner: iam.OwnerRole, admin: "admin", editor: "editor", other: "editor"}, held)

	res, err = engine.RemoveGroupMembers(ctx, iam.UserActor(admin.ID), root, []iam.Subject{editor, stranger})
	require.NoError(t, err)
	require.NoError(t, res[0].Err)
	require.NoError(t, res[1].Err, "removing a non-member is a no-op")
	require.NoError(t, unassignRole(ctx, engine, iam.UserActor(admin.ID), root, other, "admin"), "unassigning a role not held is a no-op")

	// A banned actor is not live, whatever roles it still holds.
	require.NoError(t, engine.BanUser(ctx, admin.ID, nil, nil, owner.ID))
	_, err = engine.AssignGroupRoles(ctx, iam.UserActor(admin.ID), root, []iam.Subject{editor}, "editor")
	require.ErrorIs(t, err, iam.ErrInsufficientRoleAuthority)

	// MFA-required roles bind the operator too.
	engine.cfg.TwoFactor.Mode = iam.TwoFactorOptional
	roles.Roles = append([]Role(nil), roles.Roles...)
	roles.Roles[0].RequiresMFA = true
	engine.groupSchema, err = roles.schema()
	require.NoError(t, err)
	require.ErrorIs(t, assignRole(ctx, engine, iam.OperatorActor(), root, editor, "editor"), iam.ErrTwoFAEnrollmentRequired)
}

// Root is the widest scope: a root role's persona permissions apply in every
// group of that persona, for checks and for CAP/COVER alike, while root:
// permissions count only on root and never stand in for persona ones.
func TestRootRolesApplyInEveryGroup(t *testing.T) {
	pg := testdb.ScratchPostgres(t)
	engine := mustNewWithKeys(t, Config{Token: TokenConfig{Issuer: "https://root-scope.test"},
		TwoFactor: TwoFactorConfig{Mode: iam.TwoFactorDisabled}, Roles: RoleConfig{
			Personas: map[string]Persona{"org": {Permissions: []string{"org:catalog:read"}}},
			Roles: []Role{
				{Persona: iam.RootPersona, Name: "org-admin", Permissions: []string{"org:*"}},
				{Persona: iam.RootPersona, Name: "banner", Permissions: []string{iam.PermRootUsersBan}},
				{Persona: "org", Name: "member", Permissions: []string{"org:catalog:read"}},
			},
		}}, keyset{}, Deps{Postgres: pg.Pool})
	ctx := t.Context()
	newUser := func(name string) iam.Subject {
		u, err := engine.CreateUser(ctx, name+"@example.test", name)
		require.NoError(t, err)
		return iam.UserSubject(u.ID)
	}
	founder, orgAdmin, banner, siteOwner, member := newUser("founder"), newUser("orgadmin"), newUser("banner"), newUser("siteowner"), newUser("member")
	_, err := engine.EnsureRootGroup(ctx)
	require.NoError(t, err)
	acme := iam.GroupBySlug("org", "acme")
	_, err = engine.CreatePermissionGroup(ctx, iam.CreatePermissionGroupRequest{Persona: "org", InstanceSlug: "acme", OwnerSubjectID: founder.ID})
	require.NoError(t, err)
	root := iam.RootGroup()
	grantRole(t, engine, root, orgAdmin, "org-admin")
	grantRole(t, engine, root, banner, "banner")
	grantRole(t, engine, root, siteOwner, iam.OwnerRole)
	can := func(s iam.Subject, g iam.GroupRef, p iam.Perm) bool {
		t.Helper()
		ok, err := engine.Can(ctx, s, g, p)
		require.NoError(t, err)
		return ok
	}

	require.True(t, can(orgAdmin, acme, "org:members:manage"))
	require.NoError(t, assignRole(ctx, engine, iam.UserActor(orgAdmin.ID), acme, member, "member"))
	require.NoError(t, assignRole(ctx, engine, iam.UserActor(orgAdmin.ID), acme, member, iam.OwnerRole), "org:* on root covers the org owner role")
	require.True(t, can(banner, root, iam.PermRootUsersBan))
	require.False(t, can(banner, acme, iam.PermRootUsersBan), "root permissions count only on root")
	require.False(t, can(siteOwner, acme, "org:members:manage"), "root:* never stands in for a persona permission")
	require.ErrorIs(t, assignRole(ctx, engine, iam.UserActor(siteOwner.ID), acme, member, "member"), iam.ErrInsufficientRoleAuthority)
}

// escalationFixture is an org persona with a bounded manager role and two
// groups owned by founder: acme, where the actors hold manager, and other.
type escalationFixture struct {
	engine         *engine
	founder        iam.Subject
	acme, other    iam.GroupRef
	acmeID         string
	newUser        func(string) iam.Subject
	manager, appID string
}

func newEscalationFixture(t *testing.T) escalationFixture {
	t.Helper()
	pg := testdb.ScratchPostgres(t)
	e := mustNewWithKeys(t, Config{Token: TokenConfig{Issuer: "https://escalation.test"},
		TwoFactor: TwoFactorConfig{Mode: iam.TwoFactorDisabled}, Roles: RoleConfig{
			Personas: map[string]Persona{"org": {Permissions: []string{"org:catalog:read"}, APIKeys: true, RemoteApplications: true}},
			Roles: []Role{
				{Persona: "org", Name: "member", Permissions: []string{"org:catalog:read"}},
				{Persona: "org", Name: "manager", Permissions: []string{"org:members:manage", "org:credentials:manage", "org:catalog:read"}},
				{Persona: iam.RootPersona, Name: "moderator", Permissions: []string{iam.PermRootUsersBan}},
				{Persona: iam.RootPersona, Name: "org-admin", Permissions: []string{"org:*", iam.PermRootUsersBan}},
			},
		}}, keyset{}, Deps{Postgres: pg.Pool})
	ctx := t.Context()
	n := 0
	f := escalationFixture{engine: e, acme: iam.GroupBySlug("org", "acme"), other: iam.GroupBySlug("org", "other")}
	f.newUser = func(prefix string) iam.Subject {
		n++
		u, err := e.CreateUser(ctx, fmt.Sprintf("%s%d@escalation.test", prefix, n), fmt.Sprintf("%s%d", prefix, n))
		require.NoError(t, err)
		return iam.UserSubject(u.ID)
	}
	f.founder = f.newUser("founder")
	_, err := e.EnsureRootGroup(ctx)
	require.NoError(t, err)
	f.acmeID, err = e.CreatePermissionGroup(ctx, iam.CreatePermissionGroupRequest{Persona: "org", InstanceSlug: "acme", OwnerSubjectID: f.founder.ID})
	require.NoError(t, err)
	_, err = e.CreatePermissionGroup(ctx, iam.CreatePermissionGroupRequest{Persona: "org", InstanceSlug: "other", OwnerSubjectID: f.founder.ID})
	require.NoError(t, err)
	manager := f.newUser("manager")
	f.manager = manager.ID
	grantRole(t, e, f.acme, manager, "manager")
	app, err := e.UpsertRemoteApplication(ctx, iam.RemoteApplication{Slug: "acme-app", Issuer: "https://acme-app.escalation.test", JWKSURI: "https://acme-app.escalation.test/jwks", PermissionGroupID: f.acmeID, Enabled: true})
	require.NoError(t, err)
	f.appID = app.ID
	grantRole(t, e, f.acme, iam.RemoteApplicationSubject(app.ID), "manager")
	return f
}

// No escalation, for every actor kind: an actor holding the bounded manager
// role in acme (directly, as its API key, as its application, or through a
// delegation) can grant only what it covers, strips no role above its own,
// and has no authority in another group or beyond its ceiling.
func TestRoleOperationsNeverEscalate(t *testing.T) {
	f := newEscalationFixture(t)
	ctx := t.Context()
	key, _, err := f.engine.MintAPIKey(ctx, f.acme, iam.APIKeyMintOptions{Name: "manager-key", Role: "manager", CreatedBy: f.founder.ID})
	require.NoError(t, err)
	actors := map[string]iam.Actor{
		"user":                  iam.UserActor(f.manager),
		"api_key":               iam.APIKeyActor(key.ID),
		"remote_application":    iam.RemoteApplicationActor(f.appID),
		"delegated_local":       iam.DelegatedActor(iam.DelegatedGrant{Issuer: "https://escalation.test", Subject: f.manager, Permissions: []iam.Perm{"org:*"}}),
		"delegated_application": iam.DelegatedActor(iam.DelegatedGrant{Issuer: "https://acme-app.escalation.test", Subject: "customer", Permissions: []iam.Perm{"org:*"}, RemoteApplicationID: f.appID, GroupID: f.acmeID}),
	}
	for name, actor := range actors {
		t.Run(name, func(t *testing.T) {
			fresh := f.newUser(name)
			require.NoError(t, assignRole(ctx, f.engine, actor, f.acme, fresh, "member"), "a covered role is grantable")
			require.NoError(t, removeMember(ctx, f.engine, actor, f.acme, fresh))
			for op, err := range map[string]error{
				"grant owner":          assignRole(ctx, f.engine, actor, f.acme, f.newUser(name), iam.OwnerRole),
				"replace the owner":    assignRole(ctx, f.engine, actor, f.acme, f.founder, "member"),
				"unassign the owner":   unassignRole(ctx, f.engine, actor, f.acme, f.founder, iam.OwnerRole),
				"remove the owner":     removeMember(ctx, f.engine, actor, f.acme, f.founder),
				"promote itself":       assignRole(ctx, f.engine, actor, f.acme, iam.UserSubject(f.manager), iam.OwnerRole),
				"act in another group": assignRole(ctx, f.engine, actor, f.other, f.newUser(name), "member"),
				"act beyond a ceiling": assignRole(ctx, f.engine, actor.Within("org:catalog:read"), f.acme, f.newUser(name), "member"),
			} {
				require.Error(t, err, op)
				require.True(t, errors.Is(err, iam.ErrRoleAssignmentEscalation) || errors.Is(err, iam.ErrInsufficientRoleAuthority), "%s: %v", op, err)
			}
		})
	}
	t.Run("foreign_delegation", func(t *testing.T) {
		foreign := iam.DelegatedActor(iam.DelegatedGrant{Issuer: "https://foreign.test", Subject: f.manager, Permissions: []iam.Perm{"org:*"}})
		require.ErrorIs(t, assignRole(ctx, f.engine, foreign, f.acme, f.newUser("foreign"), "member"), iam.ErrInsufficientRoleAuthority)
	})
	t.Run("operator", func(t *testing.T) {
		require.NoError(t, assignRole(ctx, f.engine, iam.OperatorActor(), f.acme, f.newUser("op"), iam.OwnerRole))
		require.ErrorIs(t, removeMember(ctx, f.engine, iam.OperatorActor(), f.other, f.founder), iam.ErrCannotRemoveLastAdminRole)
	})
	roles, err := f.engine.GroupRoles(ctx, f.acme, []iam.Subject{f.founder, iam.UserSubject(f.manager)})
	require.NoError(t, err)
	require.Equal(t, map[iam.Subject]iam.Role{f.founder: iam.OwnerRole, iam.UserSubject(f.manager): "manager"}, roles)
}

// ACCT covers the target's grants in root and in every group it holds a role
// in, and a banned actor holds no authority at all.
func TestAccountAuthorityCoversEveryGroup(t *testing.T) {
	f := newEscalationFixture(t)
	ctx := t.Context()
	moderator, orgAdmin := f.newUser("moderator"), f.newUser("orgadmin")
	grantRole(t, f.engine, iam.RootGroup(), moderator, "moderator")
	grantRole(t, f.engine, iam.RootGroup(), orgAdmin, "org-admin")
	account := func(a iam.Actor, target iam.Subject) error {
		return f.engine.withAuthorityMutation(ctx, func(st *permissionGroupStore) error {
			return f.engine.requireAccount(ctx, st, a, target.ID, iam.PermRootUsersBan)
		})
	}
	require.ErrorIs(t, account(iam.UserActor(moderator.ID), f.founder), iam.ErrAccountAuthorityEscalation, "a group owner outranks a bare site moderator")
	require.NoError(t, account(iam.UserActor(orgAdmin.ID), f.founder), "org:* on root covers every org role")
	require.NoError(t, account(iam.UserActor(moderator.ID), f.newUser("plain")))
	require.ErrorIs(t, account(iam.UserActor(f.manager), f.newUser("plain")), iam.ErrInsufficientRoleAuthority, "no root:users:ban")
	require.NoError(t, account(iam.OperatorActor(), f.founder))
	_, err := f.engine.pg.Exec(ctx, `UPDATE users SET banned_at=now() WHERE id=$1::uuid`, orgAdmin.ID)
	require.NoError(t, err)
	require.ErrorIs(t, account(iam.UserActor(orgAdmin.ID), f.newUser("plain")), iam.ErrInsufficientRoleAuthority, "a banned actor's token carries no authority")
}

// A credential never outlives its issuer: once the creator is banned or
// deleted, the lifecycle sweep revokes every key and link they issued.
func TestCredentialsOfDeadCreatorsAreRevoked(t *testing.T) {
	f := newEscalationFixture(t)
	ctx := t.Context()
	for _, end := range []string{"ban", "delete"} {
		t.Run(end, func(t *testing.T) {
			creator := f.newUser("creator")
			grantRole(t, f.engine, f.acme, creator, "manager")
			key, _, err := f.engine.MintAPIKey(ctx, f.acme, iam.APIKeyMintOptions{Name: end + "-key", Role: "member", CreatedBy: creator.ID})
			require.NoError(t, err)
			link, err := f.engine.CreateGroupInviteLink(ctx, iam.CreateGroupInviteLinkRequest{Persona: "org", InstanceSlug: "acme", Role: "member", InvitedBy: creator.ID})
			require.NoError(t, err)
			if end == "ban" {
				require.NoError(t, f.engine.BanUser(ctx, creator.ID, nil, nil, f.founder.ID))
			} else {
				require.NoError(t, f.engine.SoftDeleteUser(ctx, creator.ID))
			}
			require.NoError(t, f.engine.withAuthorityMutation(ctx, func(st *permissionGroupStore) error {
				return f.engine.revokeCredentialsOf(ctx, st, creator.ID)
			}))
			keys, err := f.engine.ListAPIKeys(ctx, f.acme)
			require.NoError(t, err)
			for _, k := range keys {
				if k.ID == key.ID {
					require.NotNil(t, k.RevokedAt, "the key outlived its creator")
				}
			}
			_, err = f.engine.RedeemGroupInviteLink(ctx, link.Code, f.newUser("redeemer").ID)
			require.ErrorIs(t, err, iam.ErrInviteLinkRevoked)
		})
	}
}
