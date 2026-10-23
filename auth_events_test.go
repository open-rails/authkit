package authkit_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/open-rails/authkit"
	"github.com/open-rails/authkit/authtest"
	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/testdb"
	"github.com/open-rails/helpers/eventlog"
	"github.com/stretchr/testify/require"
)

func TestEventReaderEmbeddedAndHTTPParity(t *testing.T) {
	pg := testdb.ScratchPostgres(t)
	cfg := testConfig(t)
	cfg.HTTP = testHTTPConfig()
	cfg.TwoFactor.Mode = iam.TwoFactorDisabled
	cfg.Roles = authkit.NewRoles()
	role := cfg.Roles.Tenant.Role("event-reader", cfg.Roles.Tenant.Users.Read)
	embedded := newPublicRuntime(t, cfg, pg.Pool)
	user := authtest.NewUser(t, embedded)
	_, err := embedded.SetGroupRole(t.Context(), iam.SystemIdentity(), iam.GroupByID(testdb.DefaultTenantID.String()), iam.UserSubject(user.ID), role)
	require.NoError(t, err)
	token := authtest.SignIn(t, embedded, user).AccessToken
	server := httptest.NewServer(embedded.Handler())
	defer server.Close()
	remote, err := authkit.NewRemoteEventReader(authkit.RemoteEventConfig{BaseURL: server.URL + "/api/v1", HTTPClient: server.Client(), Headers: http.Header{"Authorization": []string{"Bearer " + token}}})
	require.NoError(t, err)
	unauthenticated, err := authkit.NewRemoteEventReader(authkit.RemoteEventConfig{BaseURL: server.URL + "/api/v1", HTTPClient: server.Client()})
	require.NoError(t, err)
	_, err = unauthenticated.ListEvents(t.Context(), eventlog.Query{})
	requireEventErrorCode(t, err, "unauthenticated")
	authority, err := authkit.NewRemoteEventReader(authkit.RemoteEventConfig{BaseURL: server.URL + "/api/v1", HTTPClient: server.Client(), Headers: http.Header{"Authorization": []string{"Bearer " + token}}, Authority: true})
	require.NoError(t, err)
	_, err = authority.ListEvents(t.Context(), eventlog.Query{})
	requireEventErrorCode(t, err, "forbidden")
	local := embedded.EventReader()
	q := eventlog.Query{Types: []string{"user.registered"}, Limit: 1}
	want, err := local.ListEvents(t.Context(), q)
	require.NoError(t, err)
	got, err := remote.ListEvents(t.Context(), q)
	require.NoError(t, err)
	require.Equal(t, want, got)
	require.Len(t, got.Events, 1)
	require.False(t, got.Events[0].RecordedAt.IsZero())
	require.Equal(t, "user", got.Events[0].Subject.Type)
	require.Equal(t, user.ID, got.Events[0].Subject.ID)
	// Either transport can continue the other's cursor, including empty pages.
	q.After = got.NextCursor
	want, err = local.ListEvents(t.Context(), q)
	require.NoError(t, err)
	got, err = remote.ListEvents(t.Context(), q)
	require.NoError(t, err)
	require.Equal(t, want, got)
	require.Empty(t, got.Events)
	// Unknown filters are valid, and changes to the bound filter are rejected.
	q.Types = []string{"future.event"}
	_, err = local.ListEvents(t.Context(), q)
	requireEventErrorCode(t, err, "invalid_request")
	_, err = remote.ListEvents(t.Context(), q)
	requireEventErrorCode(t, err, "invalid_request")
	q = eventlog.Query{Types: []string{"future.event"}}
	got, err = remote.ListEvents(t.Context(), q)
	require.NoError(t, err)
	require.Empty(t, got.Events)
	// Retained cursors carry deployment identity through both transports.
	_, err = pg.Pool.Exec(t.Context(), "UPDATE event_log_instance SET epoch=gen_random_uuid()")
	require.NoError(t, err)
	q.After = got.NextCursor
	_, err = local.ListEvents(t.Context(), q)
	require.ErrorIs(t, err, iam.ErrEventCursorExpired)
	_, err = remote.ListEvents(t.Context(), q)
	require.ErrorIs(t, err, iam.ErrEventCursorExpired)
	// Remote access rechecks live roles; possession of a cursor grants nothing.
	require.NoError(t, embedded.RemoveGroupMember(t.Context(), iam.SystemIdentity(), iam.GroupByID(testdb.DefaultTenantID.String()), iam.UserSubject(user.ID)))
	_, err = remote.ListEvents(t.Context(), eventlog.Query{})
	requireEventErrorCode(t, err, "forbidden")
}

func requireEventErrorCode(t *testing.T, err error, code string) {
	t.Helper()
	require.Error(t, err)
	e, ok := iam.AsError(err)
	require.True(t, ok)
	require.Equal(t, code, e.Code())
}
