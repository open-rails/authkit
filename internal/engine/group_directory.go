package engine

import (
	"context"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/db"
)

// GroupDirectory backs authkit.GroupDirectory: group reads on a schema-bound
// pool, without an engine.
type GroupDirectory struct {
	store *permissionGroupStore
	pool  *pgxpool.Pool
}

func NewGroupDirectory(pool *pgxpool.Pool, schema string) (*GroupDirectory, error) {
	if pool == nil {
		return nil, fmt.Errorf("authkit: group directory requires postgres")
	}
	schema = strings.TrimSpace(schema)
	if schema == "" {
		schema = db.DefaultSchema
	}
	if !db.ValidSchemaName(schema) {
		return nil, fmt.Errorf("authkit: invalid schema %q", schema)
	}
	bound, err := schemaPool(pool, schema)
	if err != nil {
		return nil, err
	}
	return &GroupDirectory{store: newPermissionGroupStore(bound), pool: bound}, nil
}

func (d *GroupDirectory) Close() {
	if d != nil && d.pool != nil {
		d.pool.Close()
		d.pool = nil
	}
}

func (d *GroupDirectory) GroupInstanceForSlug(ctx context.Context, group iam.GroupRef) (iam.GroupInstance, error) {
	var id string
	var err error
	if group.IsRoot() {
		id, err = d.store.RootGroupID(ctx)
	} else {
		id, err = d.store.GroupByInstanceSlug(ctx, group)
	}
	if err != nil {
		return iam.GroupInstance{}, err
	}
	return d.store.GroupInstanceByID(ctx, id)
}

func (d *GroupDirectory) GroupInstanceByID(ctx context.Context, id string) (iam.GroupInstance, error) {
	return d.store.GroupInstanceByID(ctx, strings.TrimSpace(id))
}

func (d *GroupDirectory) SearchGroupInstances(ctx context.Context, persona iam.Persona, query, afterSlug, afterID string, limit int) ([]iam.GroupInstance, error) {
	return d.store.SearchGroupInstances(ctx, persona, query, afterSlug, afterID, limit)
}
