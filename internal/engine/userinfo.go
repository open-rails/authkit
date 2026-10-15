package engine

import (
	"context"
	"strings"

	"github.com/open-rails/authkit/userinfo"

	"github.com/open-rails/authkit/internal/db"
	"github.com/open-rails/authkit/internal/naming"
)

// accountUserInfo is u as the directory shows it: its verified email (an
// unproven address may be someone else's), and its username, which is also
// its display name. AuthKit keeps no other name.
func accountUserInfo(u db.User) userinfo.User {
	c := userinfo.User{ID: u.ID, Username: naming.Canonical(deref(u.Username))}
	c.Name = c.Username
	if u.Email != nil && u.EmailVerified {
		c.Email = *u.Email
	}
	return c
}

// UserInfo returns the live accounts among ids, keyed by id; a deleted,
// purged, unknown or malformed id is absent.
func (s *Engine) UserInfo(ctx context.Context, ids []string) (map[string]userinfo.User, error) {
	return s.userInfo(ctx, s.q, ids)
}

func (s *Engine) userInfo(ctx context.Context, q *db.Queries, ids []string) (map[string]userinfo.User, error) {
	out := map[string]userinfo.User{}
	if _, err := s.tenantID(ctx); err != nil {
		return out, err
	}
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
	users, err := q.TenantUsersByIDs(ctx, db.TenantUsersByIDsParams{TenantID: s.tenantKey(ctx), Ids: valid})
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
	if _, err := s.tenantID(ctx); err != nil {
		return out, err
	}
	if query == "" || limit < 1 {
		return out, nil
	}
	if err := s.requirePG(); err != nil {
		return out, err
	}
	users, err := s.q.UserInfoSearch(ctx, db.UserInfoSearchParams{TenantID: s.tenantKey(ctx), Pattern: "%" + likeEscaper.Replace(strings.ToLower(query)) + "%", MaxRows: int64(min(limit, 1000))})
	if err != nil {
		return nil, err
	}
	for _, u := range users {
		out = append(out, accountUserInfo(u))
	}
	return out, nil
}
