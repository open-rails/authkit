package authkit

import (
	"context"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/engine"
)

// EnsureGroups prepares explicitly identified, ownerless permission groups
// from a host's migration command, after Migrate. It reads only cfg.Database,
// cfg.Roles and cfg.DefaultTenantID; it does not construct a Client, load keys,
// reconcile role assignments, start workers or contact external services.
//
// Every group needs a canonical ID and a declared non-root persona. TenantID
// defaults to cfg.DefaultTenantID. A matching live group is returned unchanged,
// including its members; a deleted group or conflicting persona/tenant is an
// error. Owners and user role assignments belong to the normal Client methods.
//
// Input validation precedes writes. Each new group and its event commit
// together using CreateGroup's normal authority locks. If a later operation
// fails, the result contains the committed prefix; retrying the entire input
// is safe. The caller retains ownership of pool.
func EnsureGroups(ctx context.Context, pool *pgxpool.Pool, cfg Config, groups []iam.NewGroup) ([]iam.Group, error) {
	return engine.EnsureGroups(ctx, pool, cfg, groups)
}
