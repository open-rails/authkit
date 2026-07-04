package authcore

import (
	"context"

	authkit "github.com/open-rails/authkit"
	"github.com/open-rails/authkit/internal/db"
)

// UsersByIDs resolves many user IDs to slim display projections (username/email)
// in ONE query — the batch read behind "resolve N authors for display" without
// N+1 single fetches. IDs that don't exist are simply absent from the result.
//
// This replaces the removed authkit/identity store's batch reads. Mutations are
// NOT exposed here on purpose: username/email writes go through UpdateUsername/
// UpdateEmail, which enforce the rename cooldown + validation that raw table
// writes (the old identity.Store) silently skipped.
func (s *Service) UsersByIDs(ctx context.Context, ids []string) (map[string]authkit.UserRef, error) {
	out := map[string]authkit.UserRef{}
	if s.pg == nil || len(ids) == 0 {
		return out, nil
	}
	q := db.New(db.ForSchema(s.pg, s.dbSchema()))
	rows, err := q.IdentityUsersByIDs(ctx, ids)
	if err != nil {
		return nil, err
	}
	for _, r := range rows {
		ref := authkit.UserRef{ID: r.ID}
		if r.Username != nil {
			ref.Username = *r.Username
		}
		if r.Email != nil {
			ref.Email = *r.Email
		}
		out[r.ID] = ref
	}
	return out, nil
}
