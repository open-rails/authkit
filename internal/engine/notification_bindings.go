package engine

import (
	"context"
	"errors"
	"fmt"
	"slices"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/config"
	"github.com/open-rails/authkit/internal/db"
	migrations "github.com/open-rails/authkit/internal/migrations/notifications"
	"github.com/open-rails/migratekit"
)

var ErrNotificationScopeConflict = errors.New("authkit: notification scope belongs to a different account directory")

func notificationScope(cfg *config.NotificationsConfig, tenant iam.TenantID) string {
	if scope, ok := cfg.Scopes[tenant.String()]; ok {
		return scope
	}
	return "authkit:" + tenant.String()
}

func notificationBindingMigrations(ctx context.Context, pool *pgxpool.Pool, schema string, validate bool) error {
	chain, err := migratekit.LoadFromFS(migrations.FS)
	if err != nil {
		return err
	}
	m, err := migratekit.NewPostgresFromPGXPool(pool, "authkit-notifications")
	if err != nil {
		return err
	}
	defer m.Close()
	m = m.WithSchema(schema).WithStrictIntegrity()
	if validate {
		if err := m.ValidateAllApplied(ctx, chain); err != nil {
			return fmt.Errorf("%w: run MigrateNotifications: %w", ErrMigrationsRequired, err)
		}
		return nil
	}
	return m.ApplyMigrations(ctx, chain)
}

// bindNotificationScope is an account-directory ownership claim. It is checked
// against persisted rows, so two separately configured replicas cannot alias
// one legacy inbox scope to different tenants or account schemas.
func bindNotificationScope(ctx context.Context, q db.DBTX, database config.DatabaseConfig, cfg *config.NotificationsConfig, tenant iam.TenantID, write bool) error {
	if cfg == nil {
		return nil
	}
	if tenant.IsZero() {
		return iam.ErrTenantRequired
	}
	table := pgx.Identifier{cfg.Schema, "account_inbox_scopes"}.Sanitize()
	scope := notificationScope(cfg, tenant)
	if write {
		var exists bool
		if err := q.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM `+pgx.Identifier{database.Schema, "tenants"}.Sanitize()+` WHERE id=$1)`, tenant.String()).Scan(&exists); err != nil {
			return err
		}
		if !exists {
			return iam.ErrTenantNotFound
		}
		if _, err := q.Exec(ctx, `INSERT INTO `+table+`(scope,tenant_id,account_schema) VALUES($1,$2,$3) ON CONFLICT DO NOTHING`, scope, tenant.String(), database.Schema); err != nil {
			return err
		}
	}
	var owner, schema string
	err := q.QueryRow(ctx, `SELECT tenant_id::text,account_schema FROM `+table+` WHERE scope=$1`, scope).Scan(&owner, &schema)
	if errors.Is(err, pgx.ErrNoRows) {
		return fmt.Errorf("%w: notification scope is unbound or tenant has another inbox home", ErrNotificationScopeConflict)
	}
	if err != nil {
		return err
	}
	if owner != tenant.String() || schema != database.Schema {
		return ErrNotificationScopeConflict
	}
	return nil
}

func notificationConfiguredBindings(ctx context.Context, pool *pgxpool.Pool, database config.DatabaseConfig, cfg *config.NotificationsConfig, defaultTenant iam.TenantID, write bool) error {
	if cfg == nil {
		return nil
	}
	tenants := []string{}
	if !defaultTenant.IsZero() {
		tenants = append(tenants, defaultTenant.String())
	}
	for key := range cfg.Scopes {
		tenants = append(tenants, key)
	}
	for _, producer := range cfg.Producers {
		tenants = append(tenants, producer.TenantID.String())
	}
	slices.Sort(tenants)
	tenants = slices.Compact(tenants)
	return pgx.BeginFunc(ctx, pool, func(tx pgx.Tx) error {
		for _, raw := range tenants {
			tenant, err := iam.ParseTenantID(raw)
			if err != nil {
				return err
			}
			if err := bindNotificationScope(ctx, tx, database, cfg, tenant, write); err != nil {
				return err
			}
		}
		return nil
	})
}

func (s *Engine) checkNotificationScope(ctx context.Context, q db.DBTX) error {
	tenant, err := s.tenantID(ctx)
	if err != nil {
		return err
	}
	return bindNotificationScope(ctx, q, s.cfg.Database, s.cfg.Notifications, tenant, false)
}
