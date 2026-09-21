package embedded

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Resolve the actual session identity before changing the database. Pool
// configuration may name a different login when the host uses SET ROLE.
func migrationRuntimeUser(ctx context.Context, admin, runtime *pgxpool.Pool) (string, error) {
	if runtime == nil {
		return "", nil
	}
	var user, runtimeDB, adminDB string
	if err := runtime.QueryRow(ctx, "SELECT current_user, current_database()").Scan(&user, &runtimeDB); err != nil {
		return "", fmt.Errorf("authkit: identify runtime database user: %w", err)
	}
	if err := admin.QueryRow(ctx, "SELECT current_database()").Scan(&adminDB); err != nil {
		return "", fmt.Errorf("authkit: identify migration database: %w", err)
	}
	if runtimeDB != adminDB {
		return "", fmt.Errorf("authkit: migration and runtime pools must use the same database")
	}
	return user, nil
}

func grantMigrationRuntimeAccess(ctx context.Context, pool *pgxpool.Pool, user, schema, riverSchema string) error {
	if user == "" {
		return nil
	}
	tx, err := pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("authkit: begin runtime access provisioning: %w", err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	// AuthKit and OpenRails use the same lock because ACL writes can share
	// public schema objects even when their application schemas differ.
	if _, err := tx.Exec(ctx, "SELECT pg_advisory_xact_lock(hashtextextended('open-rails:runtime-access',0))"); err != nil {
		return fmt.Errorf("authkit: lock runtime access provisioning: %w", err)
	}
	role := pgx.Identifier{user}.Sanitize()
	namespace := pgx.Identifier{schema}.Sanitize()
	grants := []string{
		"GRANT USAGE ON SCHEMA " + namespace + " TO " + role,
		"GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA " + namespace + " TO " + role,
		"GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA " + namespace + " TO " + role,
		"GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA " + namespace + " TO " + role,
	}
	if riverSchema != "" {
		grants = append(grants, "GRANT USAGE ON SCHEMA "+pgx.Identifier{riverSchema}.Sanitize()+" TO "+role)
		// Only River's runtime objects are shared. Its migration ledger and
		// unrelated host tables in public remain outside this initializer's ACLs.
		for _, table := range []string{"river_job", "river_queue", "river_leader", "river_notification"} {
			grants = append(grants, "GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE "+pgx.Identifier{riverSchema, table}.Sanitize()+" TO "+role)
		}
		for _, sequence := range []string{"river_job_id_seq", "river_notification_id_seq"} {
			grants = append(grants, "GRANT USAGE, SELECT ON SEQUENCE "+pgx.Identifier{riverSchema, sequence}.Sanitize()+" TO "+role)
		}
	}
	for _, grant := range grants {
		if _, err := tx.Exec(ctx, grant); err != nil {
			return fmt.Errorf("authkit: provision runtime access for %q: %w", user, err)
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("authkit: commit runtime access provisioning: %w", err)
	}
	return nil
}
