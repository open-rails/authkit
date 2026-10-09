package authkit

import (
	"context"
	"log/slog"
	"net/http"

	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/errmodel"
	"github.com/open-rails/authkit/internal/ident"
	"github.com/open-rails/authkit/verify"
	"github.com/open-rails/helpers/auth"
)

// The Client is helpers/auth Auth: the middleware a library that serves a
// merchant's routes (OpenRails) mounts them with. Its gates are verify's over
// the Client, so they stack and verify a request once. Config.Merchant names
// the group that controls the merchant.
var _ auth.Auth = (*Client)(nil)

// Required is verify.RequireSession over the Client: a person signed in
// (a user's token, a device key's included), the session checked live, so a
// revoked sign-in or a banned or deleted account is 401 session_revoked. An
// API key or a remote application is 403 forbidden: it reaches merchant
// routes through RequirePermission.
func (a *Client) Required() func(http.Handler) http.Handler {
	return verify.RequireSession(a)
}

// RequirePermission is verify.RequirePermissionOn over the Client in the
// group Config.Merchant names: permission is one concrete permission the
// catalog registers (it panics on a pattern or an unregistered one, like
// RequirePermissionOn), checked live. A role covers it as Can decides, by the
// permission or a pattern over it such as the group owner's `merchant:*`.
// Without Config.Merchant it refuses every request: 401 without a valid
// credential, else 403 forbidden.
func (a *Client) RequirePermission(permission string) func(http.Handler) http.Handler {
	m := a.engine.Config().Merchant
	switch {
	case m.Root:
		return verify.RequirePermissionOn(a, iam.RootGroup(), ident.Perm(permission))
	case m.Group != "":
		return verify.RequirePermissionOn(a, iam.GroupByID(m.Group), ident.Perm(permission))
	}
	a.noMerchant.Do(func() {
		slog.Warn("authkit: RequirePermission refuses every request: Config.Merchant names no group", "permission", permission)
	})
	required := verify.Required(a)
	return func(http.Handler) http.Handler {
		return required(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			iam.WriteError(w, errmodel.E(errmodel.CodeForbidden))
		}))
	}
}

// Sensitive is verify.Sensitive over the Client: a person's own sign-in
// within the last 15 minutes, with the second factor when the account has
// one, else 403 step_up_required with the account's step-up methods. A
// machine has no sign-in of its own: 403 forbidden.
func (a *Client) Sensitive() func(http.Handler) http.Handler {
	return verify.Sensitive(a)
}

// Caller is who a gate over the Client verified for the request whose
// context ctx is (verify.CallerFromContext): a person by user id, a device
// key's included, or a Machine (an API key, a remote application). Access
// tokens carry no contact details, so a person's are read from the account;
// they are display only, and empty when the read fails.
func (a *Client) Caller(ctx context.Context) (auth.Caller, bool) {
	c, ok := verify.CallerFromContext(ctx, a)
	if !ok || c.Machine || c.Email != "" || c.Username != "" {
		return c, ok
	}
	if u, err := a.User(ctx, iam.UserByID(c.ID)); err == nil {
		c.Username, c.EmailVerified = u.Username, u.EmailVerified
		if u.Email != nil {
			c.Email = *u.Email
		}
	}
	return c, true
}
