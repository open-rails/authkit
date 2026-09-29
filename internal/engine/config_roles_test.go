package engine

import (
	"testing"

	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/ident"
	"github.com/open-rails/authkit/internal/testdb"
	"github.com/open-rails/authkit/verify"
	"github.com/stretchr/testify/require"
)

// readmeRoles is README.md's roles block.
func readmeRoles() RoleConfig {
	return RoleConfig{
		Personas: map[string]Persona{
			"channel": {
				Permissions: []string{"channel:posts:edit", "channel:posts:delete", "channel:posts:approve", "channel:self:edit", "channel:self:delete"},
			},
		},
		Roles: []Role{
			{Persona: "channel", Name: "moderator", Permissions: []string{"channel:posts:*"}},
			{Persona: "root", Name: "admin", Permissions: []string{"channel:*", "root:users:*"}},
		},
	}
}

func TestRoleConfigCompiles(t *testing.T) {
	cfg := readmeRoles()
	cfg.Roles = append(cfg.Roles, Role{Persona: "channel", Name: "lead", Permissions: []string{"channel:members:manage"}, Includes: []string{"moderator"}})
	s, err := cfg.schema()
	require.NoError(t, err)
	lead, ok := s.RoleNamed(ident.Persona("channel"), "lead")
	require.True(t, ok)
	require.Equal(t, []string{"channel:members:manage", "channel:posts:*"}, lead.Permissions, "includes are flattened")
	owner, ok := s.RoleNamed(ident.Persona("channel"), "owner")
	require.True(t, ok)
	require.Equal(t, []string{"channel:*"}, owner.Permissions)
	rootOwner, ok := s.Role(iam.RootPersona, iam.RootPersona.OwnerRole())
	require.True(t, ok)
	require.True(t, rootOwner.RequiresMFA)
	for perm, known := range map[iam.Perm]bool{
		ident.Perm("channel:posts:edit"):       true,
		ident.Perm("channel:members:manage"):   true,
		ident.Perm("channel:self:edit"):        true, // the app's own: self is just a resource name
		ident.Perm("channel:self:delete"):      true,
		ident.Perm("channel:self:read"):        false, // AuthKit registers no self permissions
		ident.Perm("root:channels:delete"):     false,
		ident.Perm("channel:members:read"):     true,
		ident.Perm("channel:roles:manage"):     false, // CustomRoles is off
		ident.Perm("channel:roles:read"):       false,
		ident.Perm("channel:credentials:read"): false, // APIKeys and RemoteApplications are off
		ident.Perm("root:users:read"):          true,
		ident.Perm("root:users:ban"):           true,
		ident.Perm("root:users:delete"):        true,
		ident.Perm("root:users:manage"):        true,
		ident.Perm("root:users:invite"):        true,
		ident.Perm("root:members:read"):        true,
		ident.Perm("root:members:manage"):      true,
		ident.Perm("root:users:recover"):       false,
		ident.Perm("root:resources:read"):      false,
		ident.Perm("root:roles:manage"):        false,
		ident.Perm("root:credentials:manage"):  false,
		ident.Perm("root:self:read"):           false,
		ident.Perm("root:settings:read"):       false,
		ident.Perm("channel:settings:read"):    false,
		ident.Perm("channel:posts:pin"):        false,
		ident.Perm("channel:*"):                false,
		ident.Perm("org:posts:edit"):           false,
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
	for _, perm := range []iam.Perm{ident.Perm("org:roles:manage"), ident.Perm("org:credentials:read"), ident.Perm("org:credentials:manage"), ident.Perm("root:roles:manage"), ident.Perm("root:credentials:manage")} {
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
		"unknown persona":                 {RoleConfig{Roles: []Role{{Persona: "channel", Name: "moderator"}}}, `unknown persona "channel"`},
		"duplicate role":                  {RoleConfig{Personas: channel(), Roles: []Role{{Persona: "channel", Name: "mod"}, {Persona: "channel", Name: "mod"}}}, "declared twice"},
		"role name":                       {RoleConfig{Roles: []Role{{Persona: "root", Name: "Admin"}}}, "name must match"},
		"unregistered permission":         {RoleConfig{Personas: channel("channel:posts:edit"), Roles: []Role{{Persona: "channel", Name: "mod", Permissions: []string{"channel:posts:pin"}}}}, "matches no permission"},
		"wildcard over nothing":           {RoleConfig{Personas: channel("channel:posts:edit"), Roles: []Role{{Persona: "channel", Name: "mod", Permissions: []string{"channel:comments:*"}}}}, "matches no permission"},
		"bare wildcard":                   {RoleConfig{Roles: []Role{{Persona: "root", Name: "all", Permissions: []string{"*"}}}}, "persona segment"},
		"persona role holds root":         {RoleConfig{Personas: channel(), Roles: []Role{{Persona: "channel", Name: "mod", Permissions: []string{"root:users:ban"}}}}, "cross-persona"},
		"persona role holds other":        {RoleConfig{Personas: map[string]Persona{"channel": {}, "org": {}}, Roles: []Role{{Persona: "channel", Name: "mod", Permissions: []string{"org:*"}}}}, "cross-persona"},
		"root role undeclared":            {RoleConfig{Roles: []Role{{Persona: "root", Name: "admin", Permissions: []string{"channel:*"}}}}, `unknown persona "channel"`},
		"roles:manage needs custom roles": {RoleConfig{Personas: channel(), Roles: []Role{{Persona: "channel", Name: "mod", Permissions: []string{"channel:roles:manage"}}}}, "matches no permission"},
		"credentials need a capability":   {RoleConfig{Personas: channel(), Roles: []Role{{Persona: "channel", Name: "mod", Permissions: []string{"channel:credentials:*"}}}}, "matches no permission"},
		"no built-in self":                {RoleConfig{Roles: []Role{{Persona: "root", Name: "admin", Permissions: []string{"root:self:read"}}}}, "matches no permission"},
		"owner redefined":                 {RoleConfig{Personas: channel("channel:posts:edit"), Roles: []Role{{Persona: "channel", Name: "owner", Permissions: []string{"channel:posts:edit"}}}}, "must hold exactly"},
		"include of another persona":      {RoleConfig{Personas: channel(), Roles: []Role{{Persona: "root", Name: "admin"}, {Persona: "channel", Name: "mod", Includes: []string{"admin"}}}}, `includes unknown role "admin"`},
		"include cycle":                   {RoleConfig{Roles: []Role{{Persona: "root", Name: "a", Includes: []string{"b"}}, {Persona: "root", Name: "b", Includes: []string{"a"}}}}, "includes cycle"},
		"self include":                    {RoleConfig{Roles: []Role{{Persona: "root", Name: "a", Includes: []string{"a"}}}}, "includes cycle"},
		"MFA outside the catalog":         {RoleConfig{Personas: map[string]Persona{"channel": {Permissions: []string{"channel:posts:edit"}, RequireMFA: []string{"channel:posts:pin"}}}}, "matches no permission"},
		"MFA of another persona":          {RoleConfig{Personas: map[string]Persona{"channel": {RequireMFA: []string{"root:users:ban"}}}}, `must start with "channel:"`},
		"MFA bare wildcard":               {RoleConfig{Personas: map[string]Persona{"channel": {RequireMFA: []string{"*"}}}}, "persona segment"},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := tc.cfg.schema()
			require.ErrorContains(t, err, tc.want)
		})
	}
}

// TestRolesWorkflow drives README's rulebook through the real engine: root
// roles apply in every group, an app catalog may name any resource, and an
// unregistered permission fails closed.
func TestRolesWorkflow(t *testing.T) {
	pg := testdb.ScratchPostgres(t)
	ctx := t.Context()
	a, err := newWithKeys(Config{TwoFactor: TwoFactorConfig{Mode: iam.TwoFactorDisabled}, Roles: readmeRoles()}, keyset{}, Deps{Postgres: pg.Pool, River: RiverFromHost()})
	require.NoError(t, err)
	t.Cleanup(a.Close)
	user := func(name string) iam.Subject {
		u, err := a.createUser(ctx, name+"@roles.test", name)
		require.NoError(t, err)
		return iam.UserSubject(u.ID)
	}
	admin, bob, carol := user("rolesadmin"), user("rolesbob"), user("rolescarol")
	grantRole(t, a, iam.RootGroup(), admin, "admin")

	owner := func(s iam.Subject) *iam.Subject { return &s }
	ann, err := a.CreateGroup(ctx, iam.NewGroup{Persona: ident.Persona("channel"), Owner: owner(admin)}, nil)
	require.NoError(t, err)
	announcements := iam.GroupByID(ann.ID)
	gl, err := a.CreateGroup(ctx, iam.NewGroup{Persona: ident.Persona("channel"), Owner: owner(bob)}, nil)
	require.NoError(t, err)
	golang := iam.GroupByID(gl.ID)
	grantRole(t, a, golang, carol, "moderator")

	can := func(s iam.Subject, g iam.GroupRef, perm iam.Perm) bool {
		t.Helper()
		ok, err := a.Can(ctx, actorOf(s), g, perm)
		require.NoError(t, err)
		return ok
	}
	require.True(t, can(admin, golang, ident.Perm("channel:posts:delete")), "a role held on root applies in every group")
	require.True(t, can(bob, golang, ident.Perm("channel:self:delete")), "the owner holds every channel permission")
	require.False(t, can(bob, announcements, ident.Perm("channel:self:delete")), "in its own channel only")
	require.True(t, can(admin, announcements, ident.Perm("channel:self:delete")))
	require.False(t, can(carol, golang, ident.Perm("channel:self:edit")), "moderators can't edit the channel")
	require.True(t, can(carol, golang, ident.Perm("channel:posts:approve")))
	require.False(t, can(carol, announcements, ident.Perm("channel:posts:approve")), "a channel role applies only in its group")
	require.False(t, can(carol, golang, ident.Perm("channel:members:manage")))

	_, err = a.Can(ctx, actorOf(carol), golang, ident.Perm("channel:posts:pin"))
	require.ErrorIs(t, err, iam.ErrUnknownPermission)
	_, err = a.Can(ctx, actorOf(carol), golang, ident.Perm("channel:self:read"))
	require.ErrorIs(t, err, iam.ErrUnknownPermission)
	require.True(t, a.KnownPermission(ident.Perm("channel:posts:edit")))
	require.False(t, a.KnownPermission(ident.Perm("channel:posts:pin")))
	require.NotPanics(t, func() { verify.RequirePermission(a, ident.Perm("channel:posts:edit")) })
	require.Panics(t, func() { verify.RequirePermission(a, ident.Perm("channel:posts:pin")) })
}
