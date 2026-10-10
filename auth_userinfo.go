package authkit

import (
	"context"
	"errors"

	"github.com/open-rails/helpers/userinfo"

	"github.com/open-rails/authkit/iam"
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

// RemoteUserInfo is the group ref's directory of the remote application
// issuer, as a library's userinfo.Lookup keyed by the issuer's subject (an
// access token's sub): the users the application pushed over SCIM, or its
// tokens' contact claims recorded (docs/scim.md). An inactive user is absent;
// an email is one the issuer asserts; the name is the display name, else the
// full name. A deleted or unknown group holds nobody.
func (a *Client) RemoteUserInfo(ref iam.GroupRef, issuer string) userinfo.Lookup {
	return remoteUserLookup{a, ref, issuer}
}

type remoteUserLookup struct {
	client *Client
	ref    iam.GroupRef
	issuer string
}

// group is the live group the lookup reads, "" for none.
func (l remoteUserLookup) group(ctx context.Context) (string, error) {
	g, err := l.client.Group(ctx, l.ref)
	switch {
	case errors.Is(err, iam.ErrGroupNotFound):
		return "", nil
	case err != nil:
		return "", err
	case g.DeletedAt != nil:
		return "", nil
	}
	return g.ID, nil
}

func (l remoteUserLookup) Get(ctx context.Context, ids []string) (map[string]userinfo.User, error) {
	g, err := l.group(ctx)
	if err != nil || g == "" {
		return map[string]userinfo.User{}, err
	}
	return l.client.engine.RemoteUserInfo(ctx, g, l.issuer, ids)
}

func (l remoteUserLookup) Search(ctx context.Context, query string, limit int) ([]userinfo.User, error) {
	if query == "" || limit < 1 {
		return []userinfo.User{}, nil
	}
	g, err := l.group(ctx)
	if err != nil || g == "" {
		return []userinfo.User{}, err
	}
	return l.client.engine.SearchRemoteUserInfo(ctx, g, l.issuer, query, limit)
}
