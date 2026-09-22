package embedded

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"
	authkit "github.com/open-rails/authkit"
	"github.com/open-rails/authkit/internal/db"
)

// lockPermissionGroup is the shared lifecycle lock. The caller supplies a
// transaction and takes this lock before role definitions, grants or invite
// rows; subsequent statements then observe the state after any waited writer.
func lockPermissionGroup(ctx context.Context, q db.DBTX, groupID string) error {
	var id string
	err := q.QueryRow(ctx, `SELECT id::text FROM permission_groups WHERE id=$1::uuid FOR UPDATE`, groupID).Scan(&id)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrGroupNotFound
	}
	return err
}

// withLockedGroup gives role definitions and grants one lifecycle boundary.
// Authorization stays in the existing caller checks, using this bound store.
func (s *Runtime) withLockedGroup(ctx context.Context, groupID string, apply func(*PermissionGroupStore) error) error {
	return s.withAuthorityMutation(ctx, func(st *PermissionGroupStore) error {
		if err := lockPermissionGroup(ctx, st.q, groupID); err != nil {
			return err
		}
		return apply(st)
	})
}

// A role must exist when a durable reference is created. Catalog definitions
// are immutable configuration; custom definitions are read under the group lock.
func (s *Runtime) requireDefinedGroupRole(ctx context.Context, st *PermissionGroupStore, groupID string, persona authkit.Persona, role authkit.Role) error {
	if _, ok := s.groupSchemaOrDefault().Role(persona, role); ok {
		return nil
	}
	resolver, err := st.CustomRolesFor(ctx, []string{groupID})
	if err != nil {
		return err
	}
	if _, ok := resolver(groupID, role); !ok {
		return authkit.ErrUnknownRole
	}
	return nil
}
