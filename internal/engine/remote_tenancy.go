package engine

import (
	"context"
	"errors"
	"github.com/open-rails/authkit/iam"
)

// A remote directory is owned through its immutable concrete group. Its
// issuer's subjects remain remote identities, never native account members.
func (s *Engine) remoteDirectoryContext(ctx context.Context, groupID string) (context.Context, iam.TenantID, error) {
	if err := s.requirePG(); err != nil {
		return nil, iam.TenantID{}, err
	}
	group, err := s.resolveGroup(ctx, s.groupStore(), iam.GroupByID(groupID))
	if err != nil {
		return nil, iam.TenantID{}, err
	}
	return s.remoteGroupContext(ctx, group)
}

func (s *Engine) remoteGroupContext(ctx context.Context, group groupTarget) (context.Context, iam.TenantID, error) {
	if group.Persona == iam.RootPersona() {
		return ctx, iam.TenantID{}, nil
	}
	selected, err := s.tenantID(ctx)
	if err != nil && !errors.Is(err, iam.ErrTenantRequired) {
		return nil, iam.TenantID{}, err
	}
	if err == nil && selected != group.TenantID {
		return nil, iam.TenantID{}, iam.ErrTenantMismatch
	}
	return WithTenant(ctx, group.TenantID), group.TenantID, nil
}

// Directory lookups never interpret the global root directory as a selected
// tenant's account membership. Source authentication and group administration
// use remoteDirectoryContext instead and retain their global root scope.
func (s *Engine) remoteLookupContext(ctx context.Context, groupID string) (context.Context, iam.TenantID, error) {
	if err := s.requirePG(); err != nil {
		return nil, iam.TenantID{}, err
	}
	group, err := s.resolveGroup(ctx, s.groupStore(), iam.GroupByID(groupID))
	if err != nil {
		return nil, iam.TenantID{}, err
	}
	return s.remoteLookupGroupContext(ctx, group)
}

func (s *Engine) remoteLookupGroupContext(ctx context.Context, group groupTarget) (context.Context, iam.TenantID, error) {
	if group.Persona == iam.RootPersona() {
		_, err := s.tenantID(ctx)
		if err == nil {
			return nil, iam.TenantID{}, iam.ErrTenantMismatch
		}
		if !errors.Is(err, iam.ErrTenantRequired) {
			return nil, iam.TenantID{}, err
		}
	}
	return s.remoteGroupContext(ctx, group)
}
