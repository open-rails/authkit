package engine

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/config"
	"github.com/open-rails/authkit/internal/db"
)

// EnsureGroups borrows the normal group lifecycle implementation without
// constructing a signing/authentication runtime. It never assigns an owner.
func EnsureGroups(ctx context.Context, log *slog.Logger, pool *pgxpool.Pool, cfg config.Config, groups []iam.NewGroup) ([]iam.Group, error) {
	if ctx == nil || pool == nil {
		return nil, errors.New("authkit: EnsureGroups needs a context and PostgreSQL pool")
	}
	schema, err := config.NormalizeSchema(cfg.Database.Schema)
	if err != nil {
		return nil, err
	}
	roles, err := config.CompileRoles(cfg.Roles)
	if err != nil {
		return nil, err
	}
	single := cfg.Tenancy == config.TenancySingle
	input := slices.Clone(groups)
	for i := range input {
		g := &input[i]
		if id, ok := canonicalUUID(g.ID); !ok || id != g.ID {
			return nil, fmt.Errorf("authkit: configured group %d needs a canonical ID", i)
		}
		if g.Owner != nil {
			return nil, errors.New("authkit: EnsureGroups does not assign owners")
		}
		if _, ok := roles.Persona(g.Persona); !ok || g.Persona == iam.RootPersona() {
			return nil, fmt.Errorf("configured group persona %q: %w", g.Persona, iam.ErrUnknownGroupPersona)
		}
		if g.TenantID.IsZero() {
			g.TenantID = cfg.DefaultTenantID
		}
		if g.TenantID.IsZero() && !single {
			return nil, iam.ErrTenantRequired
		}
	}
	if len(input) == 0 {
		return []iam.Group{}, nil
	}
	if err := validateMigrations(ctx, log, pool, cfg.Database); err != nil {
		return nil, err
	}
	// Single-tenant, every group is the database's one tenant's.
	if single {
		tenant, err := soleTenant(ctx, log, pool, cfg.Database, cfg.DefaultTenantID, false)
		if err != nil {
			return nil, err
		}
		for i := range input {
			if input[i].TenantID.IsZero() {
				input[i].TenantID = tenant
			}
			if input[i].TenantID != tenant {
				return nil, fmt.Errorf("authkit: configured group %d names tenant %s, not the single-tenant deployment's: %w", i, input[i].TenantID, iam.ErrSingleTenant)
			}
		}
		cfg.DefaultTenantID = tenant
	}
	seen := make(map[string]iam.NewGroup, len(input))
	for _, g := range input {
		if old, ok := seen[g.ID]; ok && (old.Persona != g.Persona || old.TenantID != g.TenantID) {
			return nil, iam.ErrGroupConflict
		}
		seen[g.ID] = g
	}
	owned, err := schemaPool(pool, schema, func(c *pgxpool.Config) {
		c.MaxConns, c.MinConns = 1, 0
	})
	if err != nil {
		return nil, err
	}
	defer owned.Close()
	// Only these fields are used by ownerless CreateGroup and its event log.
	// Do not normalize a full runtime config or reconcile its role catalog here.
	s := &Engine{log: log, cfg: config.Config{Tenancy: cfg.Tenancy, Database: cfg.Database, DefaultTenantID: cfg.DefaultTenantID}, pg: owned, q: db.New(owned), schema: schema, groupSchema: roles, now: time.Now}
	for _, g := range input {
		if _, err := s.Tenant(ctx, g.TenantID); err != nil {
			return nil, err
		}
		old, err := s.Group(ctx, iam.GroupByID(g.ID))
		if err != nil && !errors.Is(err, iam.ErrGroupNotFound) {
			return nil, err
		}
		if err == nil && (old.DeletedAt != nil || old.Persona != g.Persona || old.TenantID != g.TenantID) {
			return nil, iam.ErrGroupConflict
		}
	}
	out := make([]iam.Group, 0, len(input))
	for _, g := range input {
		created, err := s.CreateGroup(ctx, g)
		if err != nil {
			return out, err
		}
		out = append(out, created)
	}
	return out, nil
}
