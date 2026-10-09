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
	billingApp := authkit.RemoteApplicationConfig{Issuer: billing, RootRole: service,
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
		"no trust source":      {[]authkit.RemoteApplicationConfig{{Issuer: search}}, "jwks_uri"},
		"this deployment":      {[]authkit.RemoteApplicationConfig{{Issuer: authtest.Issuer, JWKSURI: search + "/jwks.json"}}, "reserved"},
		"a role root does not": {[]authkit.RemoteApplicationConfig{{Issuer: search, JWKSURI: search + "/jwks.json", RootRole: authkit.NewRoles().Persona("channel").Role("member")}}, "not a root role"},
	} {
		cfg.RemoteApplications = tc.apps
		_, err := newClient(t, cfg, deps)
		require.ErrorContains(t, err, tc.err, name)
	}
}
