package embedded

import (
	"context"
	"errors"
	"strings"

	authkit "github.com/open-rails/authkit"
	"github.com/open-rails/authkit/internal/db"
)

// GroupInstanceByID reads the identity already resolved by a host. It never
// interprets the UUID as a mutable name.
func (s *Service) GroupInstanceByID(ctx context.Context, groupID string) (GroupInstance, error) {
	if err := s.requirePG(); err != nil {
		return GroupInstance{}, err
	}
	return s.groupStore().GroupInstanceByID(ctx, strings.TrimSpace(groupID))
}

// CanOnGroup evaluates live assignments for the exact resolved group. A rename
// or reclaimed name cannot redirect this check to a different owner.
func (s *Service) CanOnGroup(ctx context.Context, subject authkit.Subject, groupID string, perm authkit.Perm) (bool, error) {
	if err := s.requirePG(); err != nil {
		return false, err
	}
	return s.groupStore().CanOnGroup(ctx, s.groupSchemaOrDefault(), subject, strings.TrimSpace(groupID), perm)
}

// DeleteGroupInstanceByID is the trusted host's lifecycle primitive. The host
// authorizes deletion before calling it; retries always target the captured UUID.
// ReleaseSlug releases the current name only, preserving earlier reservations.
func (s *Service) DeleteGroupInstanceByID(ctx context.Context, groupID string, opts DeletePermissionGroupOptions) error {
	if err := s.requirePG(); err != nil {
		return err
	}
	tx, err := s.pg.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	st := NewPermissionGroupStore(db.ForSchema(tx, s.dbSchema()))
	if err := st.DeleteGroup(ctx, strings.TrimSpace(groupID), opts); err != nil {
		if errors.Is(err, ErrGroupNotFound) {
			return nil
		}
		return err
	}
	return tx.Commit(ctx)
}
