package engine

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"
	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/authflow"
)

func (st *permissionGroupStore) requestGroupID(ctx context.Context, g iam.GroupRef) (string, bool, error) {
	scope, ok := authflow.ResolvedGroupFrom(ctx)
	if !ok || scope.Persona != g.Persona() || scope.Reference != g.Slug() {
		return "", false, nil
	}
	var id string
	err := st.q.QueryRow(ctx, `SELECT id::text FROM permission_groups WHERE id=$1::uuid AND persona=$2 AND deleted_at IS NULL`, scope.ID, g.Persona()).Scan(&id)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", true, iam.ErrGroupNotFound
	}
	return id, true, err
}
