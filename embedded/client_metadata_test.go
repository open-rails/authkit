package embedded

import (
	"testing"

	"github.com/google/uuid"
	"github.com/open-rails/authkit"
	"github.com/open-rails/authkit/internal/testdb"
	"github.com/stretchr/testify/require"
)

func TestClientReadsUserMetadata(t *testing.T) {
	pg := testdb.ScratchPostgres(t)
	runtime, err := NewWithKeys(Config{}, Keyset{}, Deps{Postgres: pg.Pool, River: RiverFromHost()})
	require.NoError(t, err)
	t.Cleanup(runtime.Close)
	client := runtime.Client()
	imported, err := client.ImportUsers(t.Context(), []authkit.ImportUserInput{{Email: "metadata-client@example.test", Username: "metadata-client", Metadata: map[string]any{"biography": "Public bio", "host_private": "not automatically public"}}})
	require.NoError(t, err)
	require.Equal(t, 1, imported.Inserted)
	id := imported.Results[0].UserID
	data, err := client.GetUserMetadata(t.Context(), id)
	require.NoError(t, err)
	require.Equal(t, "Public bio", data["biography"])
	require.Equal(t, "not automatically public", data["host_private"])
	data["biography"] = "local mutation"
	again, err := client.GetUserMetadata(t.Context(), id)
	require.NoError(t, err)
	require.Equal(t, "Public bio", again["biography"])
	_, err = client.GetUserMetadata(t.Context(), uuid.NewString())
	require.ErrorIs(t, err, authkit.ErrUserNotFound)
	_, err = client.GetUserMetadata(t.Context(), "")
	require.ErrorContains(t, err, "invalid_user")
}
