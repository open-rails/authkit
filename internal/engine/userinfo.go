package engine

import (
	"context"
	"strings"

	"github.com/open-rails/helpers/userinfo"

	"github.com/open-rails/authkit/internal/db"
)

// accountUserInfo is u as the directory shows it: its verified email (an
// unproven address may be someone else's), and its username, which is also
// its display name. AuthKit keeps no other name.
func accountUserInfo(u db.User) userinfo.User {
	c := userinfo.User{ID: u.ID, Username: deref(u.Username)}
	c.Name = c.Username
	if u.Email != nil && u.EmailVerified {
		c.Email = *u.Email
	}
	return c
}

// UserInfo returns the live accounts among ids, keyed by id; a deleted,
// purged, unknown or malformed id is absent.
func (s *Engine) UserInfo(ctx context.Context, ids []string) (map[string]userinfo.User, error) {
	out := map[string]userinfo.User{}
	if err := s.requirePG(); err != nil {
		return out, err
	}
	valid := make([]string, 0, len(ids))
	for _, id := range ids {
		if id, ok := canonicalUUID(id); ok {
			valid = append(valid, id)
		}
	}
	if len(valid) == 0 {
		return out, nil
	}
	users, err := s.q.UsersByIDs(ctx, valid)
	if err != nil {
		return nil, err
	}
	for _, u := range users {
		if u.DeletedAt == nil {
			out[u.ID] = accountUserInfo(u)
		}
	}
	return out, nil
}

// SearchUserInfo returns up to limit live accounts whose verified email or
// username contains query, ignoring case.
func (s *Engine) SearchUserInfo(ctx context.Context, query string, limit int) ([]userinfo.User, error) {
	out := []userinfo.User{}
	if query == "" || limit < 1 {
		return out, nil
	}
	if err := s.requirePG(); err != nil {
		return out, err
	}
	users, err := s.q.UserInfoSearch(ctx, db.UserInfoSearchParams{Pattern: "%" + likeEscaper.Replace(strings.ToLower(query)) + "%", MaxRows: int64(min(limit, 1000))})
	if err != nil {
		return nil, err
	}
	for _, u := range users {
		out = append(out, accountUserInfo(u))
	}
	return out, nil
}
