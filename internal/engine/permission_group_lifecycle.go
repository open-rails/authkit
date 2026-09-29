package engine

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"
	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/db"
)

// lockPermissionGroup is the shared lifecycle lock. The caller supplies a
// transaction and takes this lock before role definitions, grants or invite
// rows; subsequent statements then observe the state after any waited writer.
func lockPermissionGroup(ctx context.Context, q db.DBTX, groupID string) error {
	var id string
	err := q.QueryRow(ctx, `SELECT id::text FROM permission_groups WHERE id=$1::uuid AND deleted_at IS NULL FOR UPDATE`, groupID).Scan(&id)
	if errors.Is(err, pgx.ErrNoRows) {
		return iam.ErrGroupNotFound
	}
	return err
}

// withLockedGroup gives role definitions and grants one lifecycle boundary.
// Authorization stays in the existing caller checks, using this bound store.
func (s *Engine) withLockedGroup(ctx context.Context, groupID string, apply func(*permissionGroupStore) error) error {
	return s.withAuthorityMutation(ctx, func(st *permissionGroupStore) error {
		if err := lockPermissionGroup(ctx, st.q, groupID); err != nil {
			return err
		}
		return apply(st)
	})
}

// A role must exist when a durable reference is created. Catalog definitions
// are immutable configuration; custom definitions are read under the group lock.
func (s *Engine) requireDefinedGroupRole(ctx context.Context, st *permissionGroupStore, groupID string, persona iam.Persona, role iam.Role) error {
	if _, ok := s.groupSchemaOrDefault().Role(persona, role); ok {
		return nil
	}
	resolver, err := st.CustomRolesFor(ctx, []string{groupID})
	if err != nil {
		return err
	}
	if _, ok := resolver(groupID, role); !ok {
		return iam.ErrUnknownRole
	}
	return nil
}
