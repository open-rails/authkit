package authkit

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"

	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/userinfo"
)

// TransactionalUserInfo is the optional transaction-aware capability of the
// directories returned by UserInfo and RemoteUserInfo. It uses the same
// directory and ownership rules as Get, observing the host transaction's
// uncommitted changes. tx must be a READ COMMITTED transaction on this client's
// database; the lookup restores its search_path and never commits the host
// transaction. A transaction does not grant access to another tenant or group.
// The userinfo package itself remains independent of any database driver.
type TransactionalUserInfo interface {
	userinfo.Lookup
	GetTx(ctx context.Context, tx pgx.Tx, ids []string) (map[string]userinfo.User, error)
}

var _ TransactionalUserInfo = userLookup{}
var _ TransactionalUserInfo = remoteUserLookup{}

// UserInfo is the directory as a library's userinfo.Lookup, read as it is
// now: each live account's verified email (an unproven address may be someone
// else's) and its username, which is also its name. A deleted, unknown or
// malformed id is absent; search matches the verified email or username,
// ignoring case, and query is literal text.
func (a *Client) UserInfo() userinfo.Lookup { return userLookup{a} }

type userLookup struct{ client *Client }

func (l userLookup) Get(ctx context.Context, ids []string) (map[string]userinfo.User, error) {
	return l.client.engine.UserInfo(l.client.operationContext(ctx), ids)
}

func (l userLookup) GetTx(ctx context.Context, tx pgx.Tx, ids []string) (map[string]userinfo.User, error) {
	return l.client.engine.UserInfoTx(l.client.operationContext(ctx), tx, ids)
}

func (l userLookup) Search(ctx context.Context, query string, limit int) ([]userinfo.User, error) {
	return l.client.engine.SearchUserInfo(l.client.operationContext(ctx), query, limit)
}

// RemoteUserInfo is the group ref's directory of the remote application
// issuer, as a library's userinfo.Lookup keyed by the issuer's subject (an
// access token's sub): the users the application pushed over SCIM, or its
// tokens' contact claims recorded (docs/scim.md). An inactive user is absent;
// an email is one the issuer asserts; the name is the display name, else the
// full name. A deleted or unknown group holds nobody. A root-owned remote
// directory can be read only with no tenant selected; it is not membership in
// a fixed tenant. Such a mismatch returns iam.ErrTenantMismatch.
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
	return l.client.engine.RemoteUserInfo(l.client.operationContext(ctx), g, l.issuer, ids)
}

func (l remoteUserLookup) GetTx(ctx context.Context, tx pgx.Tx, ids []string) (map[string]userinfo.User, error) {
	return l.client.engine.RemoteUserInfoTx(l.client.operationContext(ctx), tx, l.ref, l.issuer, ids)
}

func (l remoteUserLookup) Search(ctx context.Context, query string, limit int) ([]userinfo.User, error) {
	if query == "" || limit < 1 {
		return []userinfo.User{}, nil
	}
	g, err := l.group(ctx)
	if err != nil || g == "" {
		return []userinfo.User{}, err
	}
	return l.client.engine.SearchRemoteUserInfo(l.client.operationContext(ctx), g, l.issuer, query, limit)
}
