package authkit

import (
	"context"
	"errors"
	"testing"

	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/testdb"
	"github.com/stretchr/testify/require"
)

func TestRuntimeConstructorOwnsTopologyWithoutRestoringRoles(t *testing.T) {
	pg := testdb.ScratchPostgres(t)
	cfg := Config{TwoFactor: TwoFactorConfig{Mode: iam.TwoFactorDisabled}, RBAC: []iam.PersonaDef{
		iam.IntrinsicRootPersona(iam.RoleDef{Name: "editor", Permissions: []string{"root:posts:edit"}}),
	}}
	first, err := NewWithKeys(cfg, Keyset{}, Deps{Postgres: pg.Pool, River: RiverFromHost()})
	require.NoError(t, err)
	t.Cleanup(first.Close)
	client := first.Client()
	_, err = client.GroupInstanceForSlug(t.Context(), iam.RootGroup())
	require.NoError(t, err, "construction installs the root without application provisioning")
	user, err := client.CreateUser(t.Context(), "constructor@example.test", "constructor")
	require.NoError(t, err)
	require.NoError(t, client.OperatorAssignGroupRole(t.Context(), iam.RootGroup(), iam.UserSubject(user.ID), "editor"))
	require.NoError(t, client.OperatorUnassignGroupRole(t.Context(), iam.RootGroup(), iam.UserSubject(user.ID), "editor"))
	first.Close()
	second, err := NewWithKeys(cfg, Keyset{}, Deps{Postgres: pg.Pool, River: RiverFromHost()})
	require.NoError(t, err)
	t.Cleanup(second.Close)
	allowed, err := second.Client().Can(t.Context(), iam.UserSubject(user.ID), iam.RootGroup(), "root:posts:edit")
	require.NoError(t, err)
	require.False(t, allowed, "restart must never restore an operator-revoked role")
}

func TestRuntimeConstructorHTTPFailureKeepsBorrowedPool(t *testing.T) {
	pg := testdb.ScratchPostgres(t)
	surface := &testHTTPSurface{}
	cfg := Config{HTTP: httpBuildFunc(func(backend HTTPBackend) (HTTPSurface, error) {
		_, err := backend.GroupInstanceForSlug(context.Background(), iam.RootGroup())
		require.NoError(t, err, "topology must exist before HTTP construction")
		return surface, errors.New("invalid HTTP policy")
	})}
	runtime, err := NewWithKeys(cfg, Keyset{}, Deps{Postgres: pg.Pool, River: RiverFromHost()})
	require.ErrorContains(t, err, "invalid HTTP policy")
	require.Nil(t, runtime)
	require.EqualValues(t, 1, surface.closed.Load())
	require.NoError(t, pg.Pool.Ping(t.Context()), "constructor cleanup must preserve the borrowed host pool")
}

func TestRuntimeConstructorWithoutRBACPreservesSharedTopology(t *testing.T) {
	pg := testdb.ScratchPostgres(t)
	owner, err := NewWithKeys(Config{TwoFactor: TwoFactorConfig{Mode: iam.TwoFactorDisabled}, RBAC: []iam.PersonaDef{iam.IntrinsicRootPersona(iam.RoleDef{Name: "editor", Permissions: []string{"root:posts:edit"}}), {Name: "merchant", Parent: iam.RootPersona}}}, Keyset{}, Deps{Postgres: pg.Pool, River: RiverFromHost()})
	require.NoError(t, err)
	t.Cleanup(owner.Close)
	user, err := owner.Client().CreateUser(t.Context(), "shared-topology@example.test", "shared-topology")
	require.NoError(t, err)
	require.NoError(t, owner.Client().OperatorAssignGroupRole(t.Context(), iam.RootGroup(), iam.UserSubject(user.ID), "editor"))
	issuer, err := NewWithKeys(Config{}, Keyset{}, Deps{Postgres: pg.Pool, River: RiverFromHost()})
	require.NoError(t, err)
	t.Cleanup(issuer.Close)
	allowed, err := owner.Client().Can(t.Context(), iam.UserSubject(user.ID), iam.RootGroup(), "root:posts:edit")
	require.NoError(t, err)
	require.True(t, allowed, "secondary issuer construction must preserve existing role authority")
	_, err = owner.Client().CreatePermissionGroup(t.Context(), iam.CreatePermissionGroupRequest{Persona: "merchant", InstanceSlug: "preserved-parent", ParentPersona: iam.RootPersona})
	require.NoError(t, err, "a second issuer with omitted RBAC must not delete the host's declared topology")
}

func TestRuntimeConcurrentConstructionSharesRoot(t *testing.T) {
	pg := testdb.ScratchPostgres(t)
	type result struct {
		runtime *Runtime
		err     error
	}
	results := make(chan result, 2)
	for range 2 {
		go func() {
			r, err := NewWithKeys(Config{}, Keyset{}, Deps{Postgres: pg.Pool, River: RiverFromHost()})
			results <- result{r, err}
		}()
	}
	var rootID string
	for range 2 {
		result := <-results
		require.NoError(t, result.err)
		t.Cleanup(result.runtime.Close)
		group, err := result.runtime.Client().GroupInstanceForSlug(t.Context(), iam.RootGroup())
		require.NoError(t, err)
		if rootID == "" {
			rootID = group.ID
		} else {
			require.Equal(t, rootID, group.ID)
		}
	}
}
