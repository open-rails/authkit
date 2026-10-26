package engine

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/config"
	"github.com/open-rails/authkit/internal/db"
)

// EnsureGroups borrows the normal group lifecycle implementation without
// constructing a signing/authentication runtime. It never assigns an owner.
func EnsureGroups(ctx context.Context, pool *pgxpool.Pool, cfg config.Config, groups []iam.NewGroup) ([]iam.Group, error) {
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
	input := slices.Clone(groups)
	seen := make(map[string]iam.NewGroup, len(input))
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
		if g.TenantID.IsZero() {
			return nil, iam.ErrTenantRequired
		}
		if old, ok := seen[g.ID]; ok && (old.Persona != g.Persona || old.TenantID != g.TenantID) {
			return nil, iam.ErrGroupConflict
		}
		seen[g.ID] = *g
	}
	if len(input) == 0 {
		return []iam.Group{}, nil
	}
	if err := validateMigrations(ctx, pool, cfg.Database); err != nil {
		return nil, err
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
	s := &Engine{cfg: config.Config{Database: cfg.Database, DefaultTenantID: cfg.DefaultTenantID}, pg: owned, q: db.New(owned), schema: schema, groupSchema: roles, now: time.Now}
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
