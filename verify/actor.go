package verify

import (
	"context"

	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/ident"
)

// ActorFromClaims derives the actor verified claims act as. It is pure and
// never yields the system. ok is false for claims that carry no AuthKit
// authority: another issuer's user, a resource access token (its authority
// is Permissions, for the resource server), a 2FA-enrollment-only token, or
// an unrecognized shape. A user or AuthKit-minted delegated actor is bound to
// the session or device key its token was minted from (iam.Actor.InSession),
// so every permission check refuses it once that sign-in is revoked.
func ActorFromClaims(c Claims) (iam.Actor, bool) {
	if c.TwoFAEnrollment {
		return iam.Actor{}, false
	}
	var a iam.Actor
	switch c.Kind {
	case iam.ActorAPIKey:
		a = iam.APIKeyActor(c.APIKeyID)
	case iam.ActorRemoteApplication:
		// The token's down-scope is a ceiling; stored grants are re-read live.
		if c.RemoteApplicationID != "" {
			a = iam.RemoteApplicationActor(c.RemoteApplicationID).Within(perms(c.Permissions)...)
		}
	case iam.ActorDelegated:
		a = iam.DelegatedActor(iam.DelegatedGrant{
			Issuer:              c.Issuer,
			Subject:             c.DelegatedSubject,
			Permissions:         perms(c.Permissions),
			RemoteApplicationID: c.RemoteApplicationID,
			GroupID:             groupID(c.Group),
		})
		// An application's delegation is its own; only AuthKit's carries the
		// minting session.
		if c.RemoteApplicationID == "" {
			a = a.InSession(c.session())
		}
	case iam.ActorUser:
		// A native token, including a device-key token. Another issuer's
		// user (Subject without UserID) has no AuthKit authority.
		if c.UserID != "" {
			a = iam.UserActor(c.UserID).InSession(c.session())
		}
	}
	return a, !a.IsZero()
}

// ActorFromContext is the actor the claims the middleware stored in ctx act
// as (ActorFromClaims), resolved once when they were stored.
func ActorFromContext(ctx context.Context) (iam.Actor, bool) {
	v, ok := ctx.Value(claimsKey{}).(verified)
	return v.actor, ok && !v.actor.IsZero()
}

// session is the sign-in the token names: sid or device_key_id.
func (c Claims) session() iam.SessionRef {
	return iam.SessionRef{SessionID: c.SessionID, DeviceKeyID: c.DeviceKeyID}
}

func groupID(g *PermissionScope) string {
	if g == nil {
		return ""
	}
	return g.GroupID
}

func perms(ps []string) []iam.Perm {
	out := make([]iam.Perm, 0, len(ps))
	for _, p := range ps {
		out = append(out, ident.Perm(p))
	}
	return out
}
