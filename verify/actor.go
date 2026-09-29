package verify

import (
	"context"
	"strings"

	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/jwtkit"
)

// ActorFromClaims derives the actor verified claims act as. It is pure and
// never yields the system. ok is false for claims that carry no AuthKit
// authority: an external user token, a 2FA-enrollment-only token (it reaches
// only AuthKit's enrollment routes), or an unrecognized shape.
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
		}
	case iam.ActorUser:
		// Native access tokens, including device-key tokens. An external
		// user (Subject without UserID) has no AuthKit authority.
		if c.TokenType == "" && c.RemoteApplicationID == "" {
			a = iam.UserActor(c.UserID)
		}
	}
	return a, !a.IsZero()
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
		out = append(out, iam.Perm(p))
	}
	return out
}
