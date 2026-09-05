package embedded

import (
	"context"
	"errors"
	"strings"

	"github.com/jackc/pgx/v5"
	authkit "github.com/open-rails/authkit"
)

type groupRequestScopeKey struct{}
type groupRequestScope struct {
	persona       authkit.Persona
	reference, id string
}

// WithResolvedGroup binds the address already resolved by an HTTP request to its
// immutable target. It confers no permission: the caller must still authorize.
// Only this exact persona/reference matches. Parent and other-target lookups keep
// normal resolution. Every use rechecks target liveness and never falls back to
// the name if the captured group has been deleted.
func WithResolvedGroup(ctx context.Context, instance authkit.GroupInstance, reference string) context.Context {
	return context.WithValue(ctx, groupRequestScopeKey{}, groupRequestScope{persona: instance.Persona, reference: strings.ToLower(strings.TrimSpace(reference)), id: instance.ID})
}

func (st *PermissionGroupStore) requestGroupID(ctx context.Context, g authkit.GroupRef) (string, bool, error) {
	scope, ok := ctx.Value(groupRequestScopeKey{}).(groupRequestScope)
	if !ok || scope.persona != g.Persona || scope.reference != strings.ToLower(strings.TrimSpace(g.Instance)) {
		return "", false, nil
	}
	var id string
	err := st.q.QueryRow(ctx, `SELECT id::text FROM profiles.permission_groups WHERE id=$1::uuid AND persona=$2`, scope.id, g.Persona).Scan(&id)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", true, ErrGroupNotFound
	}
	return id, true, err
}
