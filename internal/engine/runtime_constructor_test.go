package engine

import (
	"testing"

	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/testdb"
	"github.com/stretchr/testify/require"
)

func TestRuntimeConstructorOwnsTopologyWithoutRestoringRoles(t *testing.T) {
	pg := testdb.ScratchPostgres(t)
	cfg := Config{TwoFactor: TwoFactorConfig{Mode: iam.TwoFactorDisabled}, Roles: editorRoles()}
	first, err := newWithKeys(cfg, keyset{}, Deps{Postgres: pg.Pool, River: RiverFromHost()})
	require.NoError(t, err)
	t.Cleanup(first.Close)
	client := first
	_, err = client.Group(t.Context(), iam.RootGroup())
	require.NoError(t, err, "construction installs the root without application provisioning")
	user, err := client.createUser(t.Context(), "constructor@example.test", "constructor")
	require.NoError(t, err)
	grantRole(t, client, iam.RootGroup(), iam.UserSubject(user.ID), "editor")
	revokeRole(t, client, iam.RootGroup(), iam.UserSubject(user.ID), "editor")
	first.Close()
	second, err := newWithKeys(cfg, keyset{}, Deps{Postgres: pg.Pool, River: RiverFromHost()})
	require.NoError(t, err)
	t.Cleanup(second.Close)
	allowed, err := second.Can(t.Context(), iam.UserActor(user.ID), iam.RootGroup(), "root:posts:edit")
	require.NoError(t, err)
	require.False(t, allowed, "restart must never restore the system-revoked role")
}

// editorRoles declares an app root permission and a root role holding it.
func editorRoles() RoleConfig {
	return RoleConfig{
		Personas: map[string]Persona{"root": {Permissions: []string{"root:posts:edit"}}},
		Roles:    []Role{{Persona: iam.RootPersona, Name: "editor", Permissions: []string{"root:posts:edit"}}},
	}
}

func TestRuntimeConstructorWithoutRolesPreservesRoleAuthority(t *testing.T) {
	pg := testdb.ScratchPostgres(t)
	owner, err := newWithKeys(Config{TwoFactor: TwoFactorConfig{Mode: iam.TwoFactorDisabled}, Roles: editorRoles()}, keyset{}, Deps{Postgres: pg.Pool, River: RiverFromHost()})
	require.NoError(t, err)
	t.Cleanup(owner.Close)
	user, err := owner.createUser(t.Context(), "shared-topology@example.test", "shared-topology")
	require.NoError(t, err)
	grantRole(t, owner, iam.RootGroup(), iam.UserSubject(user.ID), "editor")
	issuer, err := newWithKeys(Config{}, keyset{}, Deps{Postgres: pg.Pool, River: RiverFromHost()})
	require.NoError(t, err)
	t.Cleanup(issuer.Close)
	allowed, err := owner.Can(t.Context(), iam.UserActor(user.ID), iam.RootGroup(), "root:posts:edit")
	require.NoError(t, err)
	require.True(t, allowed, "secondary issuer construction must preserve existing role authority")
}

func TestRuntimeConcurrentConstructionSharesRoot(t *testing.T) {
	pg := testdb.ScratchPostgres(t)
	type result struct {
		runtime *Engine
		err     error
	}
	results := make(chan result, 2)
	for range 2 {
		go func() {
			r, err := newWithKeys(Config{}, keyset{}, Deps{Postgres: pg.Pool, River: RiverFromHost()})
			results <- result{r, err}
		}()
	}
	var rootID string
	for range 2 {
		result := <-results
		require.NoError(t, result.err)
		t.Cleanup(result.runtime.Close)
		group, err := result.runtime.Group(t.Context(), iam.RootGroup())
		require.NoError(t, err)
		if rootID == "" {
			rootID = group.ID
		} else {
			require.Equal(t, rootID, group.ID)
		}
	}
}
