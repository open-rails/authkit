package engine

import (
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/config"
	"github.com/open-rails/authkit/internal/ident"
	"github.com/open-rails/authkit/internal/scim"
	"github.com/open-rails/authkit/internal/testdb"
)

// A token's contact claims record a group's user of an issuer: a new one at
// once, a held one only by newer claims that change something, so repeating
// them writes nothing. A SCIM create adopts the recorded user; a SCIM delete
// deletes it.
func TestRemoteUserClaims(t *testing.T) {
	pg := testdb.ScratchPostgres(t)
	ctx := t.Context()
	cfg := maintenanceConfig()
	roles := config.NewRoles()
	roles.Persona("merchant", config.RemoteApplications)
	cfg.Roles = roles
	e := newTestEngine(t, cfg, config.Deps{Postgres: pg.Pool})
	group, err := seedGroup(ctx, e, ident.Persona("merchant"), "")
	require.NoError(t, err)
	const issuer, sub = "https://a.example.com", "0192f6a0-0000-7000-8000-0000000000a1"
	tenant := scim.Tenant{GroupID: group, Persona: "merchant", Issuer: issuer}
	t0 := time.Now().UTC().Truncate(time.Second)
	written := func() time.Time {
		var at time.Time
		require.NoError(t, pg.Pool.QueryRow(ctx, `SELECT updated_at FROM remote_users WHERE subject = $1`, sub).Scan(&at))
		return at
	}

	_, err = e.RemoteUser(ctx, group, issuer, sub)
	require.ErrorIs(t, err, iam.ErrUserNotFound)
	require.NoError(t, e.RecordRemoteUserClaims(ctx, group, issuer, sub, RemoteUserClaims{
		Email: "ann@example.com", EmailVerified: true, Name: "Ann", Username: "ann", UpdatedAt: t0,
	}))
	u, err := e.RemoteUser(ctx, group, issuer, sub)
	require.NoError(t, err)
	require.Equal(t, RemoteUser{ID: u.ID, GroupID: group, Issuer: issuer, Subject: sub, Username: "ann", Name: "Ann", Email: "ann@example.com", Active: true,
		CreatedAt: u.CreatedAt, UpdatedAt: u.UpdatedAt}, u)
	_, err = e.RemoteUser(ctx, group, "https://c.example.com", sub)
	require.ErrorIs(t, err, iam.ErrUserNotFound, "a subject is the issuer's")

	at := written()
	require.NoError(t, e.RecordRemoteUserClaims(ctx, group, issuer, sub, RemoteUserClaims{
		Email: "ann@example.com", EmailVerified: true, Name: "Ann", Username: "ann", UpdatedAt: t0.Add(time.Minute),
	}))
	require.Equal(t, at, written(), "the same claims write nothing")
	require.NoError(t, e.RecordRemoteUserClaims(ctx, group, issuer, sub, RemoteUserClaims{Name: "Old", UpdatedAt: t0.Add(-time.Hour)}))
	require.NoError(t, e.RecordRemoteUserClaims(ctx, group, issuer, sub, RemoteUserClaims{Name: "Undated"}))
	u, _ = e.RemoteUser(ctx, group, issuer, sub)
	require.Equal(t, "Ann", u.Name, "older and undated claims keep what is held")

	require.NoError(t, e.RecordRemoteUserClaims(ctx, group, issuer, sub, RemoteUserClaims{
		Email: "unproven@example.com", Name: "Ann B", UpdatedAt: t0.Add(time.Hour),
	}))
	u, _ = e.RemoteUser(ctx, group, issuer, sub)
	require.Equal(t, "Ann B", u.Name)
	require.Equal(t, "ann@example.com", u.Email, "an unverified email claim is not recorded")
	require.Nil(t, u.ProvisionedAt)

	info, err := e.RemoteUserInfo(ctx, group, issuer, []string{sub})
	require.NoError(t, err)
	require.Equal(t, "ann@example.com", info[sub].Email)

	page, err := e.DirectoryUsers(ctx, tenant, "", 1, 10)
	require.NoError(t, err)
	require.Zero(t, page.TotalResults, "a SCIM client sees only what it provisioned")
	created, err := e.CreateDirectoryUser(ctx, tenant, scim.User{Schemas: []string{scim.SchemaUser}, ExternalID: sub, UserName: "ann.b"})
	require.NoError(t, err, "a create adopts the user claims recorded")
	require.Equal(t, u.ID, created.ID)
	_, err = e.CreateDirectoryUser(ctx, tenant, scim.User{Schemas: []string{scim.SchemaUser}, ExternalID: sub, UserName: "again"})
	require.True(t, scim.IsStatus(err, http.StatusConflict))

	require.NoError(t, e.DeleteDirectoryUser(ctx, tenant, created.ID))
	_, err = e.RemoteUser(ctx, group, issuer, sub)
	require.ErrorIs(t, err, iam.ErrUserNotFound, "a SCIM delete deletes the row")
}
