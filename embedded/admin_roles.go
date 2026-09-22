package embedded

import (
	"context"

	authkit "github.com/open-rails/authkit"
)

// AdminAssignGroupRole grants a role using trusted host-operator authority.
// This is an application Client operation, not resource initialization.
// Actor checks belong to the host; MFA and final-owner checks remain enforced.
func (s *engine) AdminAssignGroupRole(ctx context.Context, group authkit.GroupRef, subject authkit.Subject, role authkit.Role) error {
	if err := s.requirePG(); err != nil {
		return err
	}
	if group.IsRoot() {
		if _, err := s.EnsureRootGroup(ctx); err != nil {
			return err
		}
	}
	return s.AssignGroupRole(ctx, group, subject, role)
}

// AdminUnassignGroupRole revokes a role using trusted host-operator authority.
// Request paths with a user actor should call UnassignGroupRoleAs instead.
func (s *engine) AdminUnassignGroupRole(ctx context.Context, group authkit.GroupRef, subject authkit.Subject, role authkit.Role) error {
	if err := s.requirePG(); err != nil {
		return err
	}
	return s.UnassignGroupRole(ctx, group, subject, role)
}
