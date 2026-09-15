package embedded

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"
	"github.com/open-rails/authkit/internal/db"
)

// lockPermissionGroup is the shared lifecycle lock. The caller supplies a
// transaction and takes this lock before role definitions, grants or invite
// rows; subsequent statements then observe the state after any waited writer.
func lockPermissionGroup(ctx context.Context, q db.DBTX, groupID string) error {
	var id string
	err := q.QueryRow(ctx, `SELECT id::text FROM profiles.permission_groups WHERE id=$1::uuid FOR UPDATE`, groupID).Scan(&id)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrGroupNotFound
	}
	return err
}
