package identity

import (
	"context"
	"errors"
	"strings"

	"github.com/jackc/pgx/v5"
)

// Rename-history forwarding (e2e issue #58).
//
//	ForwardUserUsername — given a historical username, return the current
//	username of the user that holds it. Single-hop; rename rows always carry
//	the immutable user_id so we never need to walk a chain.
//
// The org-slug equivalent was dropped with the org plane (#111).
//
// See e2e/agents/progress.json issue #58 for the design + index choices.
// All queries hit covering indexes; sub-ms in steady state.

// ErrSlugNotFound is returned when neither the users table nor the rename
// history contains the requested slug.
var ErrSlugNotFound = errors.New("slug_not_found")

// ForwardUserUsername resolves any username — current OR historical — to the
// current username of the owning user. Returns ErrSlugNotFound when no row
// matches.
func (s *Store) ForwardUserUsername(ctx context.Context, username string) (string, error) {
	username = strings.ToLower(strings.TrimSpace(username))
	if s.pg == nil || username == "" {
		return "", ErrSlugNotFound
	}
	current, err := s.q.IdentityCurrentUsername(ctx, &username)
	if err == nil {
		return deref(current), nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return "", err
	}
	current, err = s.q.IdentityForwardUsername(ctx, username)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return "", ErrSlugNotFound
		}
		return "", err
	}
	return deref(current), nil
}
