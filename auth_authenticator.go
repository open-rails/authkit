package authkit

import (
	"context"
	"net/http"

	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/ident"
	"github.com/open-rails/authkit/verify"
	"github.com/open-rails/helpers/auth"
)

// Authenticator is the Client as a library's auth.Authenticator (OpenRails'
// Routes.Auth): it says who a request is, and the library decides what to
// admit. It admits people (their access tokens) and applications (API keys)
// alike, checked live:
//
//   - Authenticate is verify.AuthenticateSession over the Client. A user's
//     token is refused once its sign-in is revoked or its account banned or
//     deleted; an API key passes while it is live. Behind a gate over the
//     Client (verify.Required, authkitgin.Required(client), …) it reuses the
//     gate's verification. A DPoP refusal is a *auth.Challenge carrying its
//     WWW-Authenticate and DPoP-Nonce.
//   - Its Verified's Can is Client.Can in the group scope.ID names, for a
//     scope of this deployment's issuer (Scope).
//   - Its CheckRecentSignIn is verify.Sensitive's check: a stale sign-in is
//     a *auth.Challenge with auth.ErrStepUpRequired, MaxAge 15 minutes and
//     the account's step-up methods as Metadata; a credential with no
//     sign-in of its own is auth.ErrForbidden.
//   - A user acting for themself carries their email and username, read from
//     the account (access tokens carry none).
//   - It is an auth.PermissionCatalog over Config.Roles.
//
// The Client itself is not an auth.Authenticator. Like the Client's own API,
// it refuses resource access tokens (at+jwt); Verifier.Authenticator takes
// them for a resource server's audiences.
func (a *Client) Authenticator() auth.Authenticator { return authenticator{a, a} }

// Authenticator is Client.Authenticator for this Verifier's audiences, a
// resource server's: it also admits the resource access tokens (at+jwt)
// minted for them, so an OAuth client acting for itself (client
// credentials) authenticates as an application. That token holds nothing in
// a group and has no sign-in of its own. Behind a gate over this Verifier it
// reuses the gate's verification, so a DPoP proof is spent once.
func (v *Verifier) Authenticator() auth.Authenticator { return authenticator{v, v.client} }

// Scope is the group ref names as a library's Can checks it:
// {Authority: Config.Token.Issuer, ID: the group's id}. Scope(ctx,
// iam.RootGroup()) is where root roles hold their permissions. A deleted or
// unknown group is iam.ErrGroupNotFound.
func (a *Client) Scope(ctx context.Context, ref iam.GroupRef) (auth.Scope, error) {
	g, err := a.Group(ctx, ref)
	switch {
	case err != nil:
		return auth.Scope{}, err
	case g.DeletedAt != nil:
		return auth.Scope{}, iam.ErrGroupNotFound
	}
	return auth.Scope{Authority: a.engine.Config().Token.Issuer, ID: g.ID}, nil
}

type authenticator struct {
	authority verify.Authority
	client    *Client
}

var _ auth.PermissionCatalog = authenticator{}

func (a authenticator) Authenticate(r *http.Request) (auth.Verified, error) {
	if r == nil {
		return nil, auth.ErrUnauthenticated
	}
	v, err := verify.AuthenticateSession(r.Context(), a.authority, r)
	if err != nil {
		return nil, err
	}
	id := v.Identity()
	if id.SubjectKind != auth.SubjectUser || !id.SelfInvoked() || id.Email != "" || id.Username != "" {
		return v, nil
	}
	if u, err := a.client.User(r.Context(), iam.UserByID(id.Subject)); err == nil {
		id.Username, id.EmailVerified = u.Username, u.EmailVerified
		if u.Email != nil {
			id.Email = *u.Email
		}
	}
	return contacted{v, id}, nil
}

// KnownPermission reports whether permission is one registered permission,
// never a pattern.
func (a authenticator) KnownPermission(permission string) bool {
	return a.client.KnownPermission(ident.Perm(permission))
}

// contacted is a Verified whose identity carries the account's contact.
type contacted struct {
	auth.Verified
	id auth.Identity
}

func (v contacted) Identity() auth.Identity { return v.id }

func (v contacted) Can(ctx context.Context, scope auth.Scope, permission string) (bool, error) {
	c, ok := v.Verified.(auth.PermissionChecker)
	if !ok {
		return false, nil
	}
	return c.Can(ctx, scope, permission)
}

func (v contacted) CheckRecentSignIn(ctx context.Context) error {
	c, ok := v.Verified.(auth.RecentSignInChecker)
	if !ok {
		return auth.ErrForbidden
	}
	return c.CheckRecentSignIn(ctx)
}
