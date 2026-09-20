package migrations_test

import (
	"context"
	"database/sql"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/open-rails/authkit/embedded"
	"github.com/open-rails/authkit/internal/testdb"
	"github.com/stretchr/testify/require"
)

// A host can qualify AuthKit tables while keeping its own connection namespace.
// Trigger functions must also ignore temporary tables that shadow AuthKit names.
func TestSchemaQualifiedWritesKeepAuthKitTriggerScope(t *testing.T) {
	ctx := context.Background()
	pg := testdb.EmptyScratchPostgres(t)
	db, err := sql.Open("pgx", pg.URL)
	require.NoError(t, err)
	defer db.Close()
	_, err = db.ExecContext(ctx, `CREATE SCHEMA openrails`)
	require.NoError(t, err)

	for _, schema := range []string{"profiles", "custom_identity"} {
		t.Run(schema, func(t *testing.T) {
			require.NoError(t, embedded.ApplyMigrations(ctx, pg.Pool, schema))
			conn, err := db.Conn(ctx)
			require.NoError(t, err)
			defer conn.Close()
			s := pgx.Identifier{schema}.Sanitize() + "."
			_, err = conn.ExecContext(ctx, `SET search_path = openrails, public`)
			require.NoError(t, err)
			_, err = conn.ExecContext(ctx, `CREATE TEMP TABLE name_claims (LIKE `+s+`name_claims INCLUDING ALL)`)
			require.NoError(t, err)
			defer conn.ExecContext(ctx, `DROP TABLE pg_temp.name_claims`)

			var userID string
			err = conn.QueryRowContext(ctx, `INSERT INTO `+s+`users(username) VALUES ('host-user') RETURNING id::text`).Scan(&userID)
			require.NoError(t, err)
			var claims, shadowClaims int
			require.NoError(t, conn.QueryRowContext(ctx, `SELECT count(*) FROM `+s+`name_claims WHERE owner_id=$1::uuid`, userID).Scan(&claims))
			require.Equal(t, 1, claims)
			require.NoError(t, conn.QueryRowContext(ctx, `SELECT count(*) FROM pg_temp.name_claims`).Scan(&shadowClaims))
			require.Zero(t, shadowClaims)

			var credentialVersion int64
			err = conn.QueryRowContext(ctx, `UPDATE `+s+`users SET email='host@example.test' WHERE id=$1::uuid RETURNING credential_version`, userID).Scan(&credentialVersion)
			require.NoError(t, err)
			require.EqualValues(t, 2, credentialVersion)
			_, err = conn.ExecContext(ctx, `INSERT INTO `+s+`group_persona_parents(persona,parent_persona) VALUES ('merchant','root')`)
			require.NoError(t, err)
			var rootID string
			require.NoError(t, conn.QueryRowContext(ctx, `INSERT INTO `+s+`permission_groups(persona) VALUES ('root') RETURNING id::text`).Scan(&rootID))
			_, err = conn.ExecContext(ctx, `INSERT INTO `+s+`permission_groups(persona,parent_id,instance_slug) VALUES ('merchant',$1::uuid,'host-merchant')`, rootID)
			require.NoError(t, err)
			_, err = conn.ExecContext(ctx, `INSERT INTO `+s+`permission_groups(persona,parent_id,instance_slug) VALUES ('team',$1::uuid,'refused-team')`, rootID)
			var refusal *pgconn.PgError
			require.ErrorAs(t, err, &refusal)
			require.Equal(t, "23514", refusal.Code)

			_, err = conn.ExecContext(ctx, `DELETE FROM `+s+`users WHERE id=$1::uuid`, userID)
			require.NoError(t, err)
			require.NoError(t, conn.QueryRowContext(ctx, `SELECT count(*) FROM `+s+`name_claims WHERE owner_id=$1::uuid`, userID).Scan(&claims))
			require.Zero(t, claims)
			var path string
			require.NoError(t, conn.QueryRowContext(ctx, `SHOW search_path`).Scan(&path))
			require.Equal(t, "openrails, public", path)
		})
	}
}
