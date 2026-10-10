package authkit

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/config"
	"github.com/open-rails/authkit/internal/engine"
	"github.com/open-rails/authkit/internal/ident"
	"github.com/open-rails/authkit/internal/jose"
	"github.com/open-rails/authkit/verify"
	"github.com/open-rails/helpers/auth"
)

// ResourceSignInWindow is how recent an access token's sign-in (auth_time,
// RFC 9068 §2.2.1) must be for CheckRecentSignIn: AuthKit's own window.
const ResourceSignInWindow = 15 * time.Minute

// authenticateResource is Authenticate for an access token (at+jwt) minted
// for Config.Resource.ID, by this deployment or one of its trusted issuers.
func (a *Client) authenticateResource(r *http.Request) (auth.Verified, error) {
	access, err := a.engine.VerifyResourceRequest(r)
	if err != nil {
		return nil, verify.Refusal(r, err)
	}
	cl := access.Claims
	id, ok := cl.Identity()
	if !ok {
		return nil, auth.ErrUnauthenticated
	}
	v := resourceVerified{client: a, access: access, id: id, issuer: a.engine.Config().Token.Issuer}
	if g := access.Group(); g != "" {
		v.bound = auth.Scope{Authority: v.issuer, ID: g}
	}
	if access.Application == nil && cl.Kind == verify.TokenUser && id.SelfInvoked() && id.Email == "" && id.Username == "" {
		if u, err := a.User(r.Context(), iam.UserByID(id.Subject)); err == nil {
			v.id.Username, v.id.EmailVerified = u.Username, u.EmailVerified
			if u.Email != nil {
				v.id.Email = *u.Email
			}
		}
	}
	return v, nil
}

// resourceTokenRequest reports whether r presents an access token (at+jwt),
// by its unverified header: it only picks the verifier.
func resourceTokenRequest(r *http.Request) bool {
	token, _ := jose.RequestToken(r)
	typ, _, ok := jose.Unverified(token)
	return ok && (strings.EqualFold(typ, jose.ResourceAccessTokenType) || strings.EqualFold(typ, "application/"+jose.ResourceAccessTokenType))
}

// resourceVerified is a verified access token for Config.Resource.ID.
//
//   - A trusted issuer's token acts in its application's group (BoundScope)
//     with the token's permissions, within the application's live role
//     there and the ceilings of the token's scopes.
//   - This deployment's own token for a user acts as that user, live, within
//     the ceilings of its scopes and of the resource's registration.
//   - A client's own token (client credentials) holds nothing.
type resourceVerified struct {
	client *Client
	access engine.ResourceAccess
	id     auth.Identity
	issuer string
	bound  auth.Scope
}

var (
	_ auth.PermissionChecker   = resourceVerified{}
	_ auth.RecentSignInChecker = resourceVerified{}
	_ auth.Bound               = resourceVerified{}
)

func (v resourceVerified) Identity() auth.Identity { return v.id }

func (v resourceVerified) BoundScope() auth.Scope { return v.bound }

// Can checks permission live in the group scope.ID names, a scope of this
// deployment's issuer, and for a bound token only its own group.
func (v resourceVerified) Can(ctx context.Context, scope auth.Scope, permission string) (bool, error) {
	if scope.ID == "" || permission == "" || scope.Authority != v.issuer || v.bound != (auth.Scope{}) && scope != v.bound {
		return false, nil
	}
	perm := ident.Perm(permission)
	if !v.client.KnownPermission(perm) {
		return false, nil
	}
	who, ok := v.authority()
	if !ok {
		return false, nil
	}
	allowed, err := v.client.Can(ctx, who, iam.GroupByID(scope.ID), perm)
	switch {
	case errors.Is(err, iam.ErrSessionRevoked):
		return false, errors.Join(auth.ErrUnauthenticated, auth.ErrRevoked, err)
	case err != nil:
		return false, errors.Join(auth.ErrUnavailable, err)
	}
	return allowed, nil
}

// authority is the identity whose live authority the token uses, narrowed
// to what it carries; false when it carries none.
func (v resourceVerified) authority() (auth.Identity, bool) {
	cl := v.access.Claims
	var who auth.Identity
	switch app := v.access.Application; {
	case app != nil:
		who = iam.Within(iam.PinnedTo(iam.ApplicationIdentity(app.ID), app.GroupID), perms(v.access.Permissions)...)
	case cl.Kind == verify.TokenUser:
		who = iam.InSession(iam.UserIdentity(cl.Subject), iam.SessionRef{SessionID: cl.SessionID, DeviceKeyID: cl.DeviceKeyID})
		if rc, ok := config.FindResourceServer(v.client.engine.Config().AuthorizationServer, v.client.engine.Config().Resource.ID); ok {
			who = iam.Within(who, perms(rc.Permissions)...)
		}
	default:
		return auth.Identity{}, false
	}
	if v.access.Scoped {
		who = iam.Within(who, v.access.Ceilings...)
	}
	_, ok := iam.StateOf(who)
	return who, ok
}

// CheckRecentSignIn is nil when the token's user signed in within
// ResourceSignInWindow (auth_time). A stale or unknown sign-in is an RFC 9470
// step-up: insufficient_user_authentication with max_age. A token with no
// sign-in of its own (a client's) is auth.ErrForbidden.
func (v resourceVerified) CheckRecentSignIn(context.Context) error {
	cl := v.access.Claims
	if cl.Kind != verify.TokenUser || !v.id.SelfInvoked() {
		return auth.ErrForbidden
	}
	now := time.Now()
	if !cl.AuthTime.IsZero() && !cl.AuthTime.After(now.Add(time.Minute)) && now.Sub(cl.AuthTime) <= ResourceSignInWindow {
		return nil
	}
	scheme := "Bearer"
	if cl.JWKThumbprint != "" {
		scheme = "DPoP"
	}
	maxAge := int(ResourceSignInWindow / time.Second)
	return &auth.Challenge{
		Err:    errors.Join(auth.ErrStepUpRequired, errors.New("the access token's sign-in is too old")),
		MaxAge: ResourceSignInWindow,
		Header: http.Header{"Www-Authenticate": {fmt.Sprintf(`%s error="insufficient_user_authentication", error_description="A recent sign-in is required", max_age=%d`, scheme, maxAge)}},
		Metadata: map[string]any{"issuer": cl.Issuer, "max_age": maxAge},
	}
}

func perms(ps []string) []iam.Perm {
	out := make([]iam.Perm, 0, len(ps))
	for _, p := range ps {
		out = append(out, ident.Perm(p))
	}
	return out
}
