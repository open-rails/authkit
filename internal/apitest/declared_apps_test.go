package apitest_test

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/open-rails/authkit"
	"github.com/open-rails/authkit/authtest"
	"github.com/open-rails/authkit/iam"
)

// Config.RemoteApplications is the declared set: New registers it on root and
// disables what this deployment declared at an earlier boot and no longer
// does. A removed application keeps its row and role, confers nothing, and
// comes back when it is declared again. An application registered through an
// operation, or declared by a deployment sharing the store, is left alone.
func TestDeclaredRemoteApplications(t *testing.T) {
	const (
		billing = "https://billing.declared.test"
		search  = "https://search.declared.test"
		manual  = "https://manual.declared.test"
		sibling = "https://sibling.declared.test"
	)
	rbac := authkit.NewRoles()
	service := rbac.Root.Role("service", rbac.Root.Permission("orders", "write"))
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	require.NoError(t, err)
	billingApp := authkit.RemoteApplicationConfig{Issuer: billing, Role: service,
		PublicKeys: []iam.RemoteApplicationKey{{KID: "billing-1", PublicKeyPEM: string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))}}}
	searchApp := authkit.RemoteApplicationConfig{Issuer: search, JWKSURI: search + "/jwks.json"}
	declare := func(apps ...authkit.RemoteApplicationConfig) authtest.Option {
		return authtest.WithConfig(func(c *authkit.Config) { c.RemoteApplications = apps })
	}
	ctx := t.Context()
	auth, _ := authtest.New(t, authtest.WithConfig(func(c *authkit.Config) { c.Roles = rbac }), declare(billingApp, searchApp))
	app := func(auth *authkit.Client, issuer string) iam.RemoteApplication {
		t.Helper()
		a, err := auth.RemoteApplication(ctx, iam.AppByIssuer(issuer))
		require.NoError(t, err, issuer)
		return a
	}
	// What a resource server trusting the registry reads: billing is
	// trusted, with its role's grants as the ceiling, only while enabled.
	trusted := func(auth *authkit.Client) bool {
		a := app(auth, billing)
		return a.Enabled && len(a.Permissions) > 0
	}

	root, err := auth.Group(ctx, iam.RootGroup())
	require.NoError(t, err)
	for _, issuer := range []string{billing, search} {
		got := app(auth, issuer)
		require.True(t, got.Enabled, issuer)
		require.Equal(t, root.ID, got.GroupID, issuer)
		require.Equal(t, iam.ApplicationTrustRootManual, got.TrustRoot, issuer)
	}
	require.Equal(t, service, app(auth, billing).Role)
	require.True(t, trusted(auth))

	_, err = auth.UpsertRemoteApplication(ctx, iam.SystemIdentity(), iam.RootGroup(), iam.RemoteApplication{Issuer: manual, JWKSURI: manual + "/jwks.json", Enabled: true})
	require.NoError(t, err)
	authtest.Replica(t, auth, authtest.WithConfig(func(c *authkit.Config) { c.Token.Issuer = "https://sibling-deployment.declared.test" }),
		declare(authkit.RemoteApplicationConfig{Issuer: sibling, JWKSURI: sibling + "/jwks.json"}))

	// The next boot declares search alone, with new keys: billing is disabled.
	moved := searchApp
	moved.JWKSURI = search + "/keys.json"
	next := restart(t, auth, declare(moved))
	gone := app(next, billing)
	require.False(t, gone.Enabled, "an application no longer declared is disabled")
	require.Equal(t, service, gone.Role, "it keeps its role")
	require.Empty(t, gone.Permissions, "and confers nothing")
	require.False(t, trusted(next), "a disabled application is still trusted")
	require.Equal(t, moved.JWKSURI, app(next, search).JWKSURI)
	for _, issuer := range []string{search, manual, sibling} {
		require.True(t, app(next, issuer).Enabled, "%s is declared, or not this deployment's to remove", issuer)
	}

	// A removal is not repeated: an operation may enable it again.
	gone.Enabled = true
	_, err = next.UpsertRemoteApplication(ctx, iam.SystemIdentity(), iam.RootGroup(), gone)
	require.NoError(t, err)
	next = restart(t, next, declare(moved))
	require.True(t, app(next, billing).Enabled)

	// Declared again, it is the config's; declared disabled, it stays registered.
	off := billingApp
	off.Disabled = true
	next = restart(t, next, declare(off, moved))
	require.False(t, app(next, billing).Enabled)
	next = restart(t, next, declare(billingApp, moved))
	require.True(t, app(next, billing).Enabled)
	require.True(t, trusted(next))

	// Nil declares nothing and changes nothing; an empty set removes them all.
	next = restart(t, next, declare())
	require.True(t, app(next, billing).Enabled)
	next = restart(t, next, authtest.WithConfig(func(c *authkit.Config) { c.RemoteApplications = []authkit.RemoteApplicationConfig{} }))
	for issuer, enabled := range map[string]bool{billing: false, search: false, manual: true, sibling: true} {
		require.Equal(t, enabled, app(next, issuer).Enabled, issuer)
	}
	listed, err := next.ListRemoteApplications(ctx, iam.RootGroup(), iam.PageRequest{})
	require.NoError(t, err)
	require.Len(t, listed.Items, 4, "nothing is deleted")

	cfg, deps := bareConfig(t)
	for name, tc := range map[string]struct {
		apps []authkit.RemoteApplicationConfig
		err  string
	}{
		"no issuer":            {[]authkit.RemoteApplicationConfig{{JWKSURI: search + "/jwks.json"}}, "no Issuer"},
		"an issuer twice":      {[]authkit.RemoteApplicationConfig{searchApp, searchApp}, "twice"},
		"two trust sources":    {[]authkit.RemoteApplicationConfig{{Issuer: search, JWKSURI: search + "/jwks.json", PublicKeys: billingApp.PublicKeys}}, "mutually exclusive"},
		"this deployment":      {[]authkit.RemoteApplicationConfig{{Issuer: authtest.Issuer, JWKSURI: search + "/jwks.json"}}, "reserved"},
		"a role root does not": {[]authkit.RemoteApplicationConfig{{Issuer: search, JWKSURI: search + "/jwks.json", Role: authkit.NewRoles().Persona("channel").Role("member")}}, "is not a role of a"},
	} {
		cfg.RemoteApplications = tc.apps
		_, err := newClient(t, cfg, deps)
		require.ErrorContains(t, err, tc.err, name)
	}
}

// DeclareRemoteApplications is the same declared set for one group, made
// after New: each application is registered in the group with its declared
// role there, a later set disables what it no longer lists, and root's
// Config.RemoteApplications and another group's set leave each other alone.
func TestDeclaredGroupRemoteApplications(t *testing.T) {
	const (
		shop    = "https://shop.declared.test"
		staging = "https://staging.shop.declared.test"
		other   = "https://other.declared.test"
		rootApp = "https://root.declared.test"
	)
	rbac := authkit.NewRoles()
	merchant := rbac.Persona("merchant", authkit.RemoteApplications)
	read := merchant.Permission("customers", "read")
	owner, support, viewer := merchant.Persona.OwnerRole(), merchant.Role("support", read, merchant.Permission("customers", "update")), merchant.Role("viewer", read)
	ctx := t.Context()
	auth, _ := authtest.New(t, authtest.WithConfig(func(c *authkit.Config) {
		c.Roles = rbac
		c.RemoteApplications = []authkit.RemoteApplicationConfig{{Issuer: rootApp, JWKSURI: rootApp + "/jwks.json"}}
	}))
	group := func() iam.GroupRef {
		g, err := auth.CreateGroup(ctx, iam.NewGroup{Persona: merchant.Persona})
		require.NoError(t, err)
		return iam.GroupByID(g.ID)
	}
	a, b := group(), group()
	app := func(issuer string) iam.RemoteApplication {
		t.Helper()
		got, err := auth.RemoteApplication(ctx, iam.AppByIssuer(issuer))
		require.NoError(t, err, issuer)
		return got
	}
	jwks := func(issuer string) iam.RemoteApplication {
		return iam.RemoteApplication{Issuer: issuer, JWKSURI: issuer + "/jwks.json", Enabled: true}
	}
	withRole := func(app iam.RemoteApplication, role iam.Role) iam.RemoteApplication { app.Role = role; return app }

	require.NoError(t, auth.DeclareRemoteApplications(ctx, a, []iam.RemoteApplication{withRole(jwks(shop), support), jwks(staging)}))
	require.NoError(t, auth.DeclareRemoteApplications(ctx, b, []iam.RemoteApplication{withRole(jwks(other), owner)}))
	got := app(shop)
	require.Equal(t, a.ID(), got.GroupID)
	require.Equal(t, iam.ApplicationTrustRootManual, got.TrustRoot)
	require.Equal(t, support, got.Role)
	require.NotEmpty(t, got.Permissions, "its role's grants are its tokens' ceiling")
	require.True(t, app(staging).Role.IsZero(), "declared without a role, it holds none")

	// The role follows the declaration: changed, then removed.
	require.NoError(t, auth.DeclareRemoteApplications(ctx, a, []iam.RemoteApplication{withRole(jwks(shop), viewer), jwks(staging)}))
	require.Equal(t, viewer, app(shop).Role)
	require.NoError(t, auth.DeclareRemoteApplications(ctx, a, []iam.RemoteApplication{jwks(shop), jwks(staging)}))
	require.True(t, app(shop).Role.IsZero())

	// A later set disables what it no longer lists, in its group only.
	require.NoError(t, auth.DeclareRemoteApplications(ctx, a, []iam.RemoteApplication{jwks(shop)}))
	require.False(t, app(staging).Enabled)
	for _, issuer := range []string{shop, other, rootApp} {
		require.True(t, app(issuer).Enabled, issuer)
	}
	// Root's declared set at the next boot leaves the groups' alone.
	next := restart(t, auth, authtest.WithConfig(func(c *authkit.Config) { c.RemoteApplications = []authkit.RemoteApplicationConfig{} }))
	got, err := next.RemoteApplication(ctx, iam.AppByIssuer(shop))
	require.NoError(t, err)
	require.True(t, got.Enabled)
	got, err = next.RemoteApplication(ctx, iam.AppByIssuer(rootApp))
	require.NoError(t, err)
	require.False(t, got.Enabled)

	for name, tc := range map[string]struct {
		apps []iam.RemoteApplication
		err  error
	}{
		"another group's issuer":    {[]iam.RemoteApplication{jwks(other)}, iam.ErrRemoteApplicationIssuerConflict},
		"a role of another persona": {[]iam.RemoteApplication{withRole(jwks(shop), iam.RootPersona().OwnerRole())}, iam.ErrRoleNotAssignable},
		"an issuer twice":           {[]iam.RemoteApplication{jwks(shop), jwks(shop)}, iam.ErrInvalidRemoteApplication},
		"this deployment":           {[]iam.RemoteApplication{jwks(authtest.Issuer)}, iam.ErrReservedIssuer},
	} {
		require.ErrorIs(t, next.DeclareRemoteApplications(ctx, a, tc.apps), tc.err, name)
	}
	got, err = next.RemoteApplication(ctx, iam.AppByIssuer(shop))
	require.NoError(t, err)
	require.True(t, got.Enabled, "a refused set changes nothing")
}
