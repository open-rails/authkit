package verify

import (
	"context"
	"strings"

	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/ident"
	"github.com/open-rails/authkit/jwtkit"
)

// ActorFromClaims derives the actor verified claims act as. It is pure and
// never yields the system. ok is false for claims that carry no AuthKit
// authority: an external user token, a 2FA-enrollment-only token (it reaches
// only AuthKit's enrollment routes), or an unrecognized shape. A user or
// native delegated actor is bound to the session or device key its token was
// minted from (iam.Actor.InSession), so every permission check refuses it
// once that sign-in is revoked.
func ActorFromClaims(c Claims) (iam.Actor, bool) {
	if c.TwoFAEnrollment {
		return iam.Actor{}, false
	}
	var a iam.Actor
	switch c.kind() {
	case iam.ActorAPIKey:
		a = iam.APIKeyActor(c.APIKeyID)
	case iam.ActorRemoteApplication:
		if strings.EqualFold(c.TokenTyp, jwtkit.RemoteApplicationAccessTokenType) && c.UserID == "" && !c.isDelegated() {
			// The token's down-scope is a ceiling; stored grants are re-read live.
			a = iam.RemoteApplicationActor(c.RemoteApplicationID).Within(perms(c.Permissions)...)
		}
	case iam.ActorDelegated:
		if c.IsDelegatedAccessToken() {
			a = iam.DelegatedActor(iam.DelegatedGrant{
				Issuer:              c.Issuer,
				Subject:             c.DelegatedSubject,
				Permissions:         perms(c.Permissions),
				RemoteApplicationID: c.RemoteApplicationID,
				GroupID:             c.PermissionGroupID,
			})
			// An application's delegation is its own; only AuthKit's carries
			// the minting session.
			if c.RemoteApplicationID == "" {
				a = a.InSession(c.session())
			}
		}
	case iam.ActorUser:
		// Native access tokens, including device-key tokens. An external
		// user (Subject without UserID) has no AuthKit authority.
		if c.TokenType == "" && c.RemoteApplicationID == "" {
			a = iam.UserActor(c.UserID).InSession(c.session())
		}
	}
	return a, !a.IsZero()
}

// session is the sign-in the token names: sid or device_key_id.
func (c Claims) session() iam.SessionRef {
	return iam.SessionRef{SessionID: c.SessionID, DeviceKeyID: c.DeviceKeyID}
}

// ActorFromContext is ActorFromClaims over the claims Required or Optional
// middleware stored in ctx.
func ActorFromContext(ctx context.Context) (iam.Actor, bool) {
	c, ok := ClaimsFromContext(ctx)
	if !ok {
		return iam.Actor{}, false
	}
	return ActorFromClaims(c)
}

func perms(ps []string) []iam.Perm {
	out := make([]iam.Perm, 0, len(ps))
	for _, p := range ps {
		out = append(out, ident.Perm(p))
	}
	return out
}
