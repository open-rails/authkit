package authcore

import (
	"context"

	authkit "github.com/open-rails/authkit"
)

// Batch-native admin bulk mutations (#219/#222): per-item BEST-EFFORT loops over
// the corresponding single-subject operations, returning one OpResult per
// requested ID so partial failure is expressible. The single-subject methods
// remain on the internal Service for the HTTP handlers (self-delete, admin
// delete/restore routes act on exactly one subject).

func (s *Service) HardDeleteUsers(ctx context.Context, userIDs []string) ([]authkit.OpResult, error) {
	out := make([]authkit.OpResult, 0, len(userIDs))
	for _, id := range userIDs {
		out = append(out, authkit.OpResult{ID: id, Err: s.HardDeleteUser(ctx, id)})
	}
	return out, nil
}

func (s *Service) SoftDeleteUsers(ctx context.Context, userIDs []string) ([]authkit.OpResult, error) {
	out := make([]authkit.OpResult, 0, len(userIDs))
	for _, id := range userIDs {
		out = append(out, authkit.OpResult{ID: id, Err: s.SoftDeleteUser(ctx, id)})
	}
	return out, nil
}

func (s *Service) RestoreUsers(ctx context.Context, userIDs []string) ([]authkit.OpResult, error) {
	out := make([]authkit.OpResult, 0, len(userIDs))
	for _, id := range userIDs {
		out = append(out, authkit.OpResult{ID: id, Err: s.RestoreUser(ctx, id)})
	}
	return out, nil
}

// AssignRolesBySlugAs / RemoveRolesBySlugAs run the actor-checked no-escalation
// authority path (#136) PER ITEM: the actor may hold authority over some targets
// and not others, so each item carries its own authz outcome.

func (s *Service) AssignRolesBySlugAs(ctx context.Context, actorUserID string, userIDs []string, slug string) ([]authkit.OpResult, error) {
	out := make([]authkit.OpResult, 0, len(userIDs))
	for _, id := range userIDs {
		out = append(out, authkit.OpResult{ID: id, Err: s.AssignRoleBySlugAs(ctx, actorUserID, id, slug)})
	}
	return out, nil
}

func (s *Service) RemoveRolesBySlugAs(ctx context.Context, actorUserID string, userIDs []string, slug string) ([]authkit.OpResult, error) {
	out := make([]authkit.OpResult, 0, len(userIDs))
	for _, id := range userIDs {
		out = append(out, authkit.OpResult{ID: id, Err: s.RemoveRoleBySlugAs(ctx, actorUserID, id, slug)})
	}
	return out, nil
}
