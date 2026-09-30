package engine

import (
	"testing"

	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/ident"
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
		ident.Perm("channel:roles:manage"):     false,
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

	t.Run("capability built-ins", func(t *testing.T) {
		s, err := RoleConfig{Personas: map[string]Persona{
			"org":  {APIKeys: true},
			"root": {RemoteApplications: true},
		}}.schema()
		require.NoError(t, err)
		for _, perm := range []iam.Perm{ident.Perm("org:credentials:read"), ident.Perm("org:credentials:manage"), ident.Perm("root:credentials:manage")} {
			require.True(t, s.KnownPermission(perm), perm)
		}
		require.False(t, s.KnownPermission(ident.Perm("org:roles:manage")), "there are no custom roles")
	})

	// A role needs MFA when its grants reach a RequireMFA permission, however
	// it is built: a catalog role, a pattern, an include, the owner.
	t.Run("MFA follows permissions", func(t *testing.T) {
		s, err := RoleConfig{
			Personas: map[string]Persona{"channel": {
				Permissions: []string{"channel:posts:edit", "channel:posts:delete"},
				RequireMFA:  []string{"channel:posts:delete"},
				APIKeys:     true,
			}},
			Roles: []Role{
				{Persona: "channel", Name: "editor", Permissions: []string{"channel:posts:edit"}},
				{Persona: "channel", Name: "moderator", Permissions: []string{"channel:posts:*"}},
				{Persona: "channel", Name: "senior", Includes: []string{"moderator"}},
				{Persona: "root", Name: "staff", Permissions: []string{"channel:*"}},
			},
		}.schema()
		require.NoError(t, err)
		for role, want := range map[string]bool{"editor": false, "moderator": true, "senior": true, "owner": true} {
			r, ok := s.RoleNamed(ident.Persona("channel"), role)
			require.True(t, ok)
			require.Equal(t, want, r.RequiresMFA, role)
		}
		rootOwner, ok := s.Role(iam.RootPersona, iam.RootPersona.OwnerRole())
		require.True(t, ok)
		require.True(t, rootOwner.RequiresMFA, "root:members:manage always needs MFA")
	})
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
