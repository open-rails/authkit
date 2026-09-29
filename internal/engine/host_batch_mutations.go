package engine

import (
	"context"

	"github.com/open-rails/authkit/iam"
)

// Batch-native admin bulk mutations (#219/#222): per-item BEST-EFFORT loops over
// the corresponding single-subject operations, returning one OpResult per
// requested ID so partial failure is expressible. The single-subject methods
// remain on the internal engine for the HTTP handlers (self-delete and the
// admin delete route act on exactly one subject).

func (s *Engine) SoftDeleteUsers(ctx context.Context, userIDs []string) ([]iam.OpResult, error) {
	out := make([]iam.OpResult, 0, len(userIDs))
	for _, id := range userIDs {
		out = append(out, iam.OpResult{ID: id, Err: s.SoftDeleteUser(ctx, id)})
	}
	return out, nil
}
