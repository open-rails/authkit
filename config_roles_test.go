package authkit

import (
	"testing"

	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/testdb"
	"github.com/stretchr/testify/require"
)

// readmeRoles is README.md's roles block.
func readmeRoles() RoleConfig {
	return RoleConfig{
		Personas: map[string]Persona{
			"channel": {
				Permissions: []string{"channel:posts:edit", "channel:posts:delete", "channel:posts:approve"},
				Creation:    GroupCreation{Enabled: true, ReservedSlugs: []string{"announcements"}},
			},
		},
		Roles: []Role{
			{Persona: "channel", Name: "moderator", Permissions: []string{"channel:posts:*"}},
			{Persona: iam.RootPersona, Name: "admin", Permissions: []string{"channel:*", "root:users:*"}},
		},
	}
}

func TestRoleConfigCompiles(t *testing.T) {
	cfg := readmeRoles()
	cfg.Roles = append(cfg.Roles, Role{Persona: "channel", Name: "lead", Permissions: []string{"channel:members:manage"}, Includes: []iam.Role{"moderator"}})
	s, err := cfg.schema()
	require.NoError(t, err)
	lead, ok := s.Role("channel", "lead")
	require.True(t, ok)
	require.Equal(t, []string{"channel:members:manage", "channel:posts:*"}, lead.Permissions, "includes are flattened")
	owner, ok := s.Role("channel", iam.OwnerRole)
	require.True(t, ok)
	require.Equal(t, []string{"channel:*"}, owner.Permissions)
	rootOwner, ok := s.Role(iam.RootPersona, iam.OwnerRole)
	require.True(t, ok)
	require.True(t, rootOwner.RequiresMFA)
	for perm, known := range map[iam.Perm]bool{
		"channel:posts:edit":       true,
		"channel:members:manage":   true,
		"channel:self:read":        true,
		"channel:self:update":      true,
		"channel:self:delete":      true,
		"channel:members:read":     true,
		"channel:roles:manage":     false, // CustomRoles is off
		"channel:roles:read":       false,
		"channel:credentials:read": false, // APIKeys and RemoteApplications are off
		"root:users:read":          true,
		"root:users:ban":           true,
		"root:users:delete":        true,
		"root:users:manage":        true,
		"root:users:invite":        true,
		"root:members:read":        true,
		"root:members:manage":      true,
		"root:users:recover":       false,
		"root:resources:read":      false,
		"root:roles:manage":        false,
		"root:credentials:manage":  false,
		"root:self:read":           false,
		"root:settings:read":       false,
		"channel:settings:read":    false,
		"channel:posts:pin":        false,
		"channel:*":                false,
		"org:posts:edit":           false,
	} {
		require.Equal(t, known, s.KnownPermission(perm), perm)
	}
}

func TestRoleConfigCapabilityBuiltins(t *testing.T) {
	s, err := RoleConfig{Personas: map[string]Persona{
		"org":  {CustomRoles: true, APIKeys: true},
		"root": {CustomRoles: true, RemoteApplications: true},
	}}.schema()
	require.NoError(t, err)
	for _, perm := range []iam.Perm{"org:roles:manage", "org:credentials:read", "org:credentials:manage", "root:roles:manage", "root:credentials:manage"} {
		require.True(t, s.KnownPermission(perm), perm)
	}
}

func TestRoleConfigRejects(t *testing.T) {
	channel := func(perms ...string) map[string]Persona {
		return map[string]Persona{"channel": {Permissions: perms}}
	}
	for name, tc := range map[string]struct {
		cfg  RoleConfig
		want string
	}{
		"persona name":                    {RoleConfig{Personas: map[string]Persona{"Channel": {}}}, "name must match"},
		"two-part permission":             {RoleConfig{Personas: channel("channel:edit")}, "exactly three segments"},
		"wildcard in catalog":             {RoleConfig{Personas: channel("channel:posts:*")}, "segment"},
		"foreign catalog entry":           {RoleConfig{Personas: channel("org:posts:edit")}, `must start with "channel:"`},
		"self is reserved":                {RoleConfig{Personas: channel("channel:self:archive")}, "reserved to AuthKit"},
		"root creation":                   {RoleConfig{Personas: map[string]Persona{"root": {Creation: GroupCreation{Enabled: true}}}}, "singleton"},
		"reserved slug":                   {RoleConfig{Personas: map[string]Persona{"channel": {Creation: GroupCreation{ReservedSlugs: []string{"no spaces"}}}}}, "reserved slug"},
		"slug pattern":                    {RoleConfig{Personas: map[string]Persona{"channel": {Creation: GroupCreation{SlugPattern: "("}}}}, "slug pattern"},
		"unknown persona":                 {RoleConfig{Roles: []Role{{Persona: "channel", Name: "moderator"}}}, `unknown persona "channel"`},
		"duplicate role":                  {RoleConfig{Personas: channel(), Roles: []Role{{Persona: "channel", Name: "mod"}, {Persona: "channel", Name: "mod"}}}, "declared twice"},
		"role name":                       {RoleConfig{Roles: []Role{{Persona: iam.RootPersona, Name: "Admin"}}}, "name must match"},
		"unregistered permission":         {RoleConfig{Personas: channel("channel:posts:edit"), Roles: []Role{{Persona: "channel", Name: "mod", Permissions: []string{"channel:posts:pin"}}}}, "matches no permission"},
		"wildcard over nothing":           {RoleConfig{Personas: channel("channel:posts:edit"), Roles: []Role{{Persona: "channel", Name: "mod", Permissions: []string{"channel:comments:*"}}}}, "matches no permission"},
		"bare wildcard":                   {RoleConfig{Roles: []Role{{Persona: iam.RootPersona, Name: "all", Permissions: []string{"*"}}}}, "persona segment"},
		"persona role holds root":         {RoleConfig{Personas: channel(), Roles: []Role{{Persona: "channel", Name: "mod", Permissions: []string{"root:users:ban"}}}}, "cross-persona"},
		"persona role holds other":        {RoleConfig{Personas: map[string]Persona{"channel": {}, "org": {}}, Roles: []Role{{Persona: "channel", Name: "mod", Permissions: []string{"org:*"}}}}, "cross-persona"},
		"root role undeclared":            {RoleConfig{Roles: []Role{{Persona: iam.RootPersona, Name: "admin", Permissions: []string{"channel:*"}}}}, `unknown persona "channel"`},
		"roles:manage needs custom roles": {RoleConfig{Personas: channel(), Roles: []Role{{Persona: "channel", Name: "mod", Permissions: []string{"channel:roles:manage"}}}}, "matches no permission"},
		"credentials need a capability":   {RoleConfig{Personas: channel(), Roles: []Role{{Persona: "channel", Name: "mod", Permissions: []string{"channel:credentials:*"}}}}, "matches no permission"},
		"root has no self":                {RoleConfig{Roles: []Role{{Persona: iam.RootPersona, Name: "admin", Permissions: []string{"root:self:read"}}}}, "matches no permission"},
		"owner redefined":                 {RoleConfig{Personas: channel("channel:posts:edit"), Roles: []Role{{Persona: "channel", Name: iam.OwnerRole, Permissions: []string{"channel:posts:edit"}}}}, "must hold exactly"},
		"include of another persona":      {RoleConfig{Personas: channel(), Roles: []Role{{Persona: iam.RootPersona, Name: "admin"}, {Persona: "channel", Name: "mod", Includes: []iam.Role{"admin"}}}}, `includes unknown role "admin"`},
		"include cycle":                   {RoleConfig{Roles: []Role{{Persona: iam.RootPersona, Name: "a", Includes: []iam.Role{"b"}}, {Persona: iam.RootPersona, Name: "b", Includes: []iam.Role{"a"}}}}, "includes cycle"},
		"self include":                    {RoleConfig{Roles: []Role{{Persona: iam.RootPersona, Name: "a", Includes: []iam.Role{"a"}}}}, "includes cycle"},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := tc.cfg.schema()
			require.ErrorContains(t, err, tc.want)
		})
	}
}

// TestRolesWorkflow drives README's rulebook through the real engine: root
// roles apply in every group, reserved slugs need <persona>:* on root, and an
// unregistered permission fails closed.
func TestRolesWorkflow(t *testing.T) {
	pg := testdb.ScratchPostgres(t)
	ctx := t.Context()
	a, err := newWithKeys(Config{TwoFactor: TwoFactorConfig{Mode: iam.TwoFactorDisabled}, Roles: readmeRoles()}, keyset{}, Deps{Postgres: pg.Pool, River: RiverFromHost()})
	require.NoError(t, err)
	t.Cleanup(a.Close)
	user := func(name string) iam.Subject {
		u, err := a.CreateUser(ctx, name+"@roles.test", name)
		require.NoError(t, err)
		return iam.UserSubject(u.ID)
	}
	admin, bob, carol := user("rolesadmin"), user("rolesbob"), user("rolescarol")
	require.NoError(t, a.OperatorAssignGroupRole(ctx, iam.RootGroup(), admin, "admin"))

	announcements := iam.GroupRef{Persona: "channel", Instance: "announcements"}
	_, err = a.engine.CreateInstanceForSubject(ctx, announcements, "", bob.ID)
	require.ErrorIs(t, err, iam.ErrGroupSlugReserved)
	created, err := a.engine.CreateInstanceForSubject(ctx, announcements, "", admin.ID)
	require.NoError(t, err)
	require.True(t, created.Created)
	golang := iam.GroupRef{Persona: "channel", Instance: "golang"}
	_, err = a.engine.CreateInstanceForSubject(ctx, golang, "", bob.ID)
	require.NoError(t, err)
	require.NoError(t, a.OperatorAssignGroupRole(ctx, golang, carol, "moderator"))

	can := func(s iam.Subject, g iam.GroupRef, perm iam.Perm) bool {
		t.Helper()
		ok, err := a.Can(ctx, s, g, perm)
		require.NoError(t, err)
		return ok
	}
	require.True(t, can(admin, golang, "channel:posts:delete"), "a role held on root applies in every group")
	require.True(t, can(bob, golang, "channel:self:delete"), "the owner holds every channel permission")
	require.True(t, can(carol, golang, "channel:posts:approve"))
	require.False(t, can(carol, announcements, "channel:posts:approve"), "a channel role applies only in its group")
	require.False(t, can(carol, golang, "channel:members:manage"))

	_, err = a.Can(ctx, carol, golang, "channel:posts:pin")
	require.ErrorIs(t, err, iam.ErrUnknownPermission)
	gid, err := a.ResolveGroupIDForSlug(ctx, golang)
	require.NoError(t, err)
	_, err = a.CanOnGroup(ctx, carol, gid, "root:self:read")
	require.ErrorIs(t, err, iam.ErrUnknownPermission)
	require.True(t, a.KnownPermission("channel:posts:edit"))
	require.False(t, a.KnownPermission("channel:posts:pin"))
	require.NotPanics(t, func() { a.RequirePermission("channel:posts:edit", nil) })
	require.Panics(t, func() { a.RequirePermission("channel:posts:pin", nil) })
}
