package authkit

import (
	"context"

	"github.com/open-rails/helpers/userinfo"

	"github.com/open-rails/authkit/internal/engine"
)

// UserInfo is the directory as a library's userinfo.Lookup, read as it is
// now: each live account's verified email (an unproven address may be someone
// else's) and its username, which is also its name. A deleted, unknown or
// malformed id is absent; search matches the verified email or username,
// ignoring case, and query is literal text.
func (a *Client) UserInfo() userinfo.Lookup { return userLookup{a.engine} }

type userLookup struct{ engine *engine.Engine }

func (l userLookup) Get(ctx context.Context, ids []string) (map[string]userinfo.User, error) {
	return l.engine.UserInfo(ctx, ids)
}

func (l userLookup) Search(ctx context.Context, query string, limit int) ([]userinfo.User, error) {
	return l.engine.SearchUserInfo(ctx, query, limit)
}
