package embedded

import (
	"context"

	authkit "github.com/open-rails/authkit"
)

// OperatorAssignGroupRole grants a role using trusted host-operator authority.
// This is an application Client operation, not resource initialization.
// Actor checks belong to the host; MFA and final-owner checks remain enforced.
func (s *engine) OperatorAssignGroupRole(ctx context.Context, group authkit.GroupRef, subject authkit.Subject, role authkit.Role) error {
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

// OperatorUnassignGroupRole revokes a role using trusted host-operator authority.
// Request paths with a user actor should call UnassignGroupRoleAs instead.
func (s *engine) OperatorUnassignGroupRole(ctx context.Context, group authkit.GroupRef, subject authkit.Subject, role authkit.Role) error {
	if err := s.requirePG(); err != nil {
		return err
	}
	return s.UnassignGroupRole(ctx, group, subject, role)
}

// OperatorApplyBootstrapManifest is the explicit operator reconciliation operation.
// Runtime construction never invokes it or restores user role assignments.
func (s *engine) OperatorApplyBootstrapManifest(ctx context.Context, manifest authkit.BootstrapManifest, opts authkit.BootstrapReconcileOptions) (authkit.BootstrapManifestResult, error) {
	return s.ApplyBootstrapManifest(ctx, manifest, opts)
}
