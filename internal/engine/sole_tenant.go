package engine

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/config"
	"github.com/open-rails/authkit/internal/db"
	"github.com/open-rails/authkit/internal/rbac"
)

// errSeveralTenants refuses a single-tenant deployment over a database that
// holds more than one tenant: the data contradicts the declared mode.
var errSeveralTenants = errors.New("authkit: the database holds more than one tenant, but Config.Tenancy is TenancySingle: a multi-tenant deployment sets Tenancy (and MigrationOptions.Tenancy) to TenancyMulti")

// soleTenant settles a single-tenant database's one tenant under the
// authority lock, so replicas booting together agree. With none, create makes
// it as CreateTenant would, under named or a new ID; one is adopted; several,
// or one other than named, are refused.
func soleTenant(ctx context.Context, log *slog.Logger, pool *pgxpool.Pool, database config.DatabaseConfig, named iam.TenantID, create bool) (iam.TenantID, error) {
	schema, err := config.NormalizeSchema(database.Schema)
	if err != nil {
		return iam.TenantID{}, err
	}
	database.Schema = schema
	owned, err := schemaPool(pool, schema, func(c *pgxpool.Config) { c.MaxConns, c.MinConns = 1, 0 })
	if err != nil {
		return iam.TenantID{}, err
	}
	defer owned.Close()
	s := &Engine{log: log, cfg: config.Config{Database: database}, pg: owned, q: db.New(owned), schema: schema, groupSchema: rbac.Default(), now: time.Now}
	var id iam.TenantID
	err = s.withAuthorityMutation(ctx, iam.SystemIdentity(), func(st *permissionGroupStore) error {
		ids, err := db.New(st.q).FirstTwoTenants(ctx)
		if err != nil {
			return err
		}
		switch len(ids) {
		case 0:
			if !create {
				return errors.New("authkit: the single-tenant database has no tenant yet: run Migrate")
			}
			if id = named; id.IsZero() {
				id = iam.NewTenantID()
			}
			return s.createTenantIn(ctx, st, id, "tenant-"+strings.ReplaceAll(id.String(), "-", ""))
		case 1:
			if id, err = iam.ParseTenantID(ids[0]); err != nil {
				return err
			}
			if !named.IsZero() && named != id {
				return fmt.Errorf("authkit: DefaultTenantID %s is not the single-tenant database's tenant %s", named, id)
			}
			return nil
		}
		return errSeveralTenants
	})
	return id, err
}

// singleTenant refuses ctx's tenant other than a single-tenant deployment's.
func (s *Engine) singleTenant(id iam.TenantID) error {
	if s.cfg.Tenancy == config.TenancySingle && !id.IsZero() && id != s.cfg.DefaultTenantID {
		return fmt.Errorf("authkit: tenant %s is not this single-tenant deployment's: %w", id, iam.ErrSingleTenant)
	}
	return nil
}

// SelectTenant is the check ForTenant and request dispatch make before
// selecting id: it exists and, single-tenant, is the deployment's tenant.
func (s *Engine) SelectTenant(ctx context.Context, id iam.TenantID) error {
	if err := s.singleTenant(id); err != nil {
		return err
	}
	_, err := s.Tenant(ctx, id)
	return err
}

// DefaultTenantID is the tenant unscoped operations act in; zero refuses them.
func (s *Engine) DefaultTenantID() iam.TenantID { return s.cfg.DefaultTenantID }

// DefaultTenant is the tenant cfg's unscoped operations act in, for work
// without a Client: single-tenant the database's one tenant, multi-tenant
// cfg.DefaultTenantID (zero when unset).
func DefaultTenant(ctx context.Context, log *slog.Logger, pool *pgxpool.Pool, cfg config.Config) (iam.TenantID, error) {
	if cfg.Tenancy != config.TenancySingle {
		return cfg.DefaultTenantID, nil
	}
	if pool == nil {
		return iam.TenantID{}, errors.New("authkit: a single-tenant deployment's tenant needs PostgreSQL")
	}
	return soleTenant(ctx, log, pool, cfg.Database, cfg.DefaultTenantID, false)
}
