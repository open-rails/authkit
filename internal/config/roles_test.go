package config

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/ident"
	"github.com/open-rails/authkit/internal/rbac"
)

// readmeRoles is README.md's roles block.
func readmeRoles() (*Roles, *PersonaDef, iam.Role) {
	r := NewRoles()
	channel := r.Persona("channel")
	for _, p := range [][2]string{{"posts", "edit"}, {"posts", "delete"}, {"posts", "approve"}, {"self", "edit"}, {"self", "delete"}} {
		channel.Permission(p[0], p[1])
	}
	moderator := channel.Role("moderator", channel.Resource("posts").All())
	r.Root.Role("admin", channel.All(), r.Root.Users.All())
	return r, channel, moderator
}

func TestCompileRoles(t *testing.T) {
	r, channel, moderator := readmeRoles()
	channel.Role("lead", channel.Members.Manage, moderator)
	s, err := CompileRoles(r)
	require.NoError(t, err)
	lead, ok := s.RoleNamed(ident.Persona("channel"), "lead")
	require.True(t, ok)
	require.Equal(t, []string{"channel:members:manage", "channel:posts:*"}, lead.Permissions, "includes are flattened")
	owner, ok := s.RoleNamed(ident.Persona("channel"), "owner")
	require.True(t, ok)
	require.Equal(t, []string{"channel:*"}, owner.Permissions)
	rootOwner, ok := s.Role(iam.RootPersona(), iam.RootPersona().OwnerRole())
	require.True(t, ok)
	require.True(t, rootOwner.RequiresMFA)
	require.Equal(t, []string{"root:*", "channel:*"}, rootOwner.Permissions, "the root owner holds every persona")
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

	t.Run("nil is root-only", func(t *testing.T) {
		s, err := CompileRoles(nil)
		require.NoError(t, err)
		require.Equal(t, []iam.Persona{iam.RootPersona()}, s.Personas())
	})

	t.Run("capability built-ins", func(t *testing.T) {
		r := NewRoles(RemoteApplications)
		r.Persona("org", APIKeys)
		s, err := CompileRoles(r)
		require.NoError(t, err)
		for _, perm := range []iam.Perm{ident.Perm("org:credentials:read"), ident.Perm("org:credentials:manage"), ident.Perm("root:credentials:manage")} {
			require.True(t, s.KnownPermission(perm), perm)
		}
		require.False(t, s.KnownPermission(ident.Perm("org:roles:manage")), "there are no custom roles")
	})

	// A role needs MFA when its grants reach a RequireMFA permission, however
	// it is built: a catalog role, a pattern, an include, the owner.
	t.Run("MFA follows permissions", func(t *testing.T) {
		r := NewRoles()
		channel := r.Persona("channel", APIKeys)
		edit, del := channel.Permission("posts", "edit"), channel.Permission("posts", "delete")
		channel.RequireMFA(del)
		channel.Role("editor", edit)
		moderator := channel.Role("moderator", channel.Resource("posts").All())
		channel.Role("senior", moderator)
		r.Root.Role("staff", channel.All())
		s, err := CompileRoles(r)
		require.NoError(t, err)
		for role, want := range map[string]bool{"editor": false, "moderator": true, "senior": true, "owner": true} {
			r, ok := s.RoleNamed(ident.Persona("channel"), role)
			require.True(t, ok)
			require.Equal(t, want, r.RequiresMFA, role)
		}
		rootOwner, ok := s.Role(iam.RootPersona(), iam.RootPersona().OwnerRole())
		require.True(t, ok)
		require.True(t, rootOwner.RequiresMFA, "root:members:manage always needs MFA")
	})
}

// TestCompileRolesRejects covers the builder's declaration errors and the
// compile step's catalog, grant and include checks. A foreign catalog entry
// or a role of an undeclared persona cannot be declared at all.
func TestCompileRolesRejects(t *testing.T) {
	withChannel := func(declare func(r *Roles, channel *PersonaDef)) func() *Roles {
		return func() *Roles {
			r := NewRoles()
			declare(r, r.Persona("channel"))
			return r
		}
	}
	for name, tc := range map[string]struct {
		roles func() *Roles
		want  string
	}{
		"persona name":           {func() *Roles { r := NewRoles(); r.Persona("Channel"); return r }, "name must match"},
		"root persona":           {func() *Roles { r := NewRoles(); r.Persona("root"); return r }, "use Roles.Root"},
		"persona declared twice": {func() *Roles { r := NewRoles(); r.Persona("channel"); r.Persona("channel"); return r }, "declared twice"},
		"permission segment":     {withChannel(func(_ *Roles, c *PersonaDef) { c.Permission("Posts", "edit") }), "each segment must match"},
		"wildcard in catalog":    {withChannel(func(_ *Roles, c *PersonaDef) { c.Permission("posts", "*") }), "each segment must match"},
		"built-in permission":    {withChannel(func(_ *Roles, c *PersonaDef) { c.Permission("members", "read") }), "is built in"},
		"permission declared twice": {withChannel(func(_ *Roles, c *PersonaDef) {
			c.Permission("posts", "edit")
			c.Permission("posts", "edit")
		}), "declared twice"},
		"duplicate role": {withChannel(func(_ *Roles, c *PersonaDef) { c.Role("mod"); c.Role("mod") }), "declared twice"},
		"role name":      {func() *Roles { r := NewRoles(); r.Root.Role("Admin"); return r }, "name must match"},
		"unregistered permission": {withChannel(func(_ *Roles, c *PersonaDef) {
			c.Permission("posts", "edit")
			c.Role("mod", ident.Perm("channel:posts:pin"))
		}), "matches no permission"},
		"wildcard over nothing": {withChannel(func(_ *Roles, c *PersonaDef) {
			c.Permission("posts", "edit")
			c.Role("mod", c.Resource("comments").All())
		}), "matches no permission"},
		"zero grant":               {func() *Roles { r := NewRoles(); r.Root.Role("all", ident.Perm("*")); return r }, "zero permission"},
		"persona role holds root":  {withChannel(func(r *Roles, c *PersonaDef) { c.Role("mod", r.Root.Users.Ban) }), "cross-persona"},
		"persona role holds other": {withChannel(func(r *Roles, c *PersonaDef) { c.Role("mod", r.Persona("org").All()) }), "cross-persona"},
		"root role undeclared": {func() *Roles {
			r := NewRoles()
			r.Root.Role("admin", ident.Perm("channel:*"))
			return r
		}, `unknown persona "channel"`},
		"roles:manage needs custom roles": {withChannel(func(_ *Roles, c *PersonaDef) { c.Role("mod", ident.Perm("channel:roles:manage")) }), "matches no permission"},
		"credentials need a capability":   {withChannel(func(_ *Roles, c *PersonaDef) { c.Role("mod", c.Credentials.All()) }), "matches no permission"},
		"no built-in self":                {func() *Roles { r := NewRoles(); r.Root.Role("admin", ident.Perm("root:self:read")); return r }, "matches no permission"},
		"owner redefined": {withChannel(func(_ *Roles, c *PersonaDef) {
			c.Role("owner", c.Permission("posts", "edit"))
		}), "built in: use Owner"},
		"include of another persona": {withChannel(func(r *Roles, c *PersonaDef) { c.Role("mod", r.Root.Role("admin")) }), "a role of another persona"},
		"include cycle": {func() *Roles {
			r := NewRoles()
			a := r.Root.Role("a", ident.Role(iam.RootPersona(), "b"))
			r.Root.Role("b", a)
			return r
		}, "includes cycle"},
		"self include": {func() *Roles { r := NewRoles(); r.Root.Role("a", ident.Role(iam.RootPersona(), "a")); return r }, "includes cycle"},
		"MFA outside the catalog": {withChannel(func(_ *Roles, c *PersonaDef) {
			c.Permission("posts", "edit")
			c.RequireMFA(ident.Perm("channel:posts:pin"))
		}), "matches no permission"},
		"MFA of another persona": {withChannel(func(r *Roles, c *PersonaDef) { c.RequireMFA(r.Root.Users.Ban) }), `must start with "channel:"`},
		"MFA bare wildcard":      {withChannel(func(_ *Roles, c *PersonaDef) { c.RequireMFA(ident.Perm("*")) }), `must start with "channel:"`},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := CompileRoles(tc.roles())
			require.ErrorContains(t, err, tc.want)
		})
	}
}

// A declared permission no role bundles is legal: the owner holds it through
// `<persona>:*` (a host may gate billing on an owner-only root permission).
func TestCompileRolesKeepsOwnerOnlyPermissions(t *testing.T) {
	r := NewRoles()
	billing := r.Root.Permission("billing", "manage")
	channel := r.Persona("channel")
	archive := channel.Permission("self", "archive")
	s, err := CompileRoles(r)
	require.NoError(t, err)
	for _, perm := range []iam.Perm{billing, archive} {
		require.True(t, s.KnownPermission(perm), perm)
		owner, ok := s.Role(perm.Persona(), perm.Persona().OwnerRole())
		require.True(t, ok)
		require.True(t, rbac.Covers(owner.Permissions, perm), "the %s owner holds %s", perm.Persona(), perm)
	}
}

// A library's published permission strings declare in one call; a built-in
// among them is returned as it is, and another persona's or a malformed one
// fails the catalog.
func TestPersonaDeclare(t *testing.T) {
	r := NewRoles()
	merchant := r.Persona("merchant", APIKeys)
	perms := merchant.Declare("merchant:payments:refund", "merchant:credentials:manage", "merchant:catalog:read")
	require.Equal(t, []string{"merchant:payments:refund", "merchant:credentials:manage", "merchant:catalog:read"}, ident.Strings(perms))
	merchant.Role("support", perms[0])
	s, err := CompileRoles(r)
	require.NoError(t, err)
	require.True(t, s.KnownPermission(perms[0]))
	require.True(t, s.KnownPermission(perms[1]))

	for _, bad := range []string{"root:payments:refund", "merchant:payments", "merchant:payments:refund:x", "merchant:payments:*", "merchant:payments:refund"} {
		r := NewRoles()
		m := r.Persona("merchant")
		m.Declare("merchant:payments:refund")
		got := m.Declare(bad)
		require.Len(t, got, 1, bad)
		_, err := CompileRoles(r)
		require.Error(t, err, bad)
	}
}
