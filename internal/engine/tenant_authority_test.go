package engine

import (
	"context"
	"errors"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/config"
	"github.com/open-rails/authkit/internal/db"
	"github.com/open-rails/authkit/internal/testdb"
	"github.com/stretchr/testify/require"
)

type tenantLookupFailure struct {
	db.DBTX
	err error
}

func (q tenantLookupFailure) QueryRow(context.Context, string, ...any) pgx.Row {
	return tenantFailureRow{q.err}
}

type tenantFailureRow struct{ err error }

func (r tenantFailureRow) Scan(...any) error { return r.err }

func TestTenantAuthorityOwnershipFailureIsNotRevocation(t *testing.T) {
	pg := testdb.ScratchPostgres(t)
	e := newTestEngine(t, maintenanceConfig(), config.Deps{Postgres: pg.Pool})
	u, err := e.CreateUser(t.Context(), iam.NewUser{Username: "authorityowner"})
	require.NoError(t, err)
	identity := iam.InSession(iam.InTenant(iam.UserIdentity(u.ID), testdb.DefaultTenantID), iam.SessionRef{SessionID: iam.NewTenantID().String()})
	failed := errors.New("temporary ownership lookup outage")
	_, err = e.identityAuthority(t.Context(), newPermissionGroupStore(tenantLookupFailure{DBTX: e.pg, err: failed}), identity, groupTarget{Persona: iam.RootPersona()})
	require.ErrorIs(t, err, failed)
	require.NotErrorIs(t, err, iam.ErrSessionRevoked, "an unavailable database is never proof of revocation")
	results, err := e.DeleteUsers(t.Context(), iam.SystemIdentity(), []string{u.ID})
	require.NoError(t, err)
	require.NoError(t, results[0].Err)
	_, err = e.identityAuthority(t.Context(), e.groupStore(), identity, groupTarget{Persona: iam.RootPersona()})
	require.ErrorIs(t, err, iam.ErrSessionRevoked, "a session whose live owner was deleted is definitively revoked")
	_, err = e.identityAuthority(t.Context(), e.groupStore(), iam.InTenant(iam.UserIdentity(u.ID), testdb.DefaultTenantID), groupTarget{Persona: iam.RootPersona()})
	require.ErrorIs(t, err, iam.ErrInsufficientAuthority, "native sessionless identities retain their account-level refusal")
}
