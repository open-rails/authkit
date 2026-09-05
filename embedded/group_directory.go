package embedded

import (
	"context"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5/pgxpool"
	authkit "github.com/open-rails/authkit"
	"github.com/open-rails/authkit/internal/authcore"
	"github.com/open-rails/authkit/internal/db"
)

// GroupDirectory reads immutable group identities and current/active alias names.
// It uses AuthKit's existing store; it carries no signer, issuer or session state.
type GroupDirectory struct {
	store *authcore.PermissionGroupStore
}

// NewGroupDirectory creates a read-only view of an already migrated schema.
// Empty schema selects profiles. Construction does not query, migrate, write or
// start workers. Hosts remain responsible for authorizing any subsequent action.
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
	return &GroupDirectory{store: authcore.NewPermissionGroupStore(db.ForSchema(pool, schema))}, nil
}

func (d *GroupDirectory) GroupInstanceForSlug(ctx context.Context, persona, reference string) (authkit.GroupInstance, error) {
	persona = strings.TrimSpace(persona)
	reference = strings.ToLower(strings.TrimSpace(reference))
	var id string
	var err error
	if persona == authcore.RootPersona {
		id, err = d.store.RootGroupID(ctx)
	} else {
		id, err = d.store.GroupByInstanceSlug(ctx, persona, reference)
	}
	if err != nil {
		return authkit.GroupInstance{}, err
	}
	return d.store.GroupInstanceByID(ctx, id)
}

func (d *GroupDirectory) GroupInstanceByID(ctx context.Context, id string) (authkit.GroupInstance, error) {
	return d.store.GroupInstanceByID(ctx, strings.TrimSpace(id))
}
