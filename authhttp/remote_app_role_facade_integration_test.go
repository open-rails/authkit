package authhttp

import (
	"context"
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"

	authkit "github.com/open-rails/authkit"
	"github.com/open-rails/authkit/embedded"
)

// #308: the Go-API remote-application role grant is actor-checked
// (no-escalation) on embedded.Client; the unchecked form lives only on
// Client.Genesis() for bootstrap/migration.
func TestRemoteApplicationRoleGrant_FacadeIsActorChecked(t *testing.T) {
	srv, client := newInstanceCreateServer(t, WithoutRateLimiter())
	ctx := context.Background()
	owner, ownerToken := newInstanceTestUser(t, srv, "facadeowner")
	require.Equal(t, http.StatusCreated, postOrg(srv, ownerToken, `{"slug":"facaderoles"}`).Code)
	gid, err := client.ResolveGroupIDForSlug(ctx, "org", "facaderoles")
	require.NoError(t, err)
	app, err := client.UpsertRemoteApplication(ctx, authkit.RemoteApplication{
		Slug: "fapp" + uniqueSuffix(), PermissionGroupID: gid, Issuer: "https://fapp.example.com/" + uniqueSuffix(),
		JWKSURI: "http://127.0.0.1:9/jwks.json", Mode: "jwks", Enabled: true,
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = embedded.Unwrap(client).DeleteRemoteApplication(ctx, app.Issuer) })
	holds := func() bool {
		can, err := client.Can(ctx, app.ID, embedded.SubjectKindRemoteApp, "org", "facaderoles", "org:catalog:read")
		require.NoError(t, err)
		return can
	}

	// credentials:manage without the role's own permissions: escalation refused.
	bounded, _ := newInstanceTestUser(t, srv, "facadebounded")
	require.NoError(t, client.Genesis().AssignGroupRole(ctx, "org", "facaderoles", bounded, embedded.SubjectKindUser, "credential-manager"))
	err = client.AssignRemoteApplicationRoleAs(ctx, bounded, "org", "facaderoles", app.Slug, "member")
	require.ErrorIs(t, err, authkit.ErrRoleAssignmentEscalation)
	require.False(t, holds())

	// No credentials:manage at all, and no actor: refused.
	member, _ := newInstanceTestUser(t, srv, "facademember")
	require.NoError(t, client.Genesis().AssignGroupRole(ctx, "org", "facaderoles", member, embedded.SubjectKindUser, "member"))
	require.Error(t, client.AssignRemoteApplicationRoleAs(ctx, member, "org", "facaderoles", app.Slug, "member"))
	require.Error(t, client.AssignRemoteApplicationRoleAs(ctx, "", "org", "facaderoles", app.Slug, "member"))
	require.False(t, holds())

	// The owner (holds org:*) grants; genesis grants with no actor at all.
	require.NoError(t, client.AssignRemoteApplicationRoleAs(ctx, owner, "org", "facaderoles", app.Slug, "member"))
	require.True(t, holds())
	require.NoError(t, client.Genesis().AssignRemoteApplicationRole(ctx, app.ID, "credential-manager"))
	can, err := client.Can(ctx, app.ID, embedded.SubjectKindRemoteApp, "org", "facaderoles", "org:credentials:manage")
	require.NoError(t, err)
	require.True(t, can)
}
