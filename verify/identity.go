package verify

import (
	"context"

	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/ident"
	"github.com/open-rails/helpers/auth"
)

// boundIdentity is the identity verified claims act as (Claims.Identity),
// carrying AuthKit's credential state (iam.CredentialState) so operations
// accept it. It is false for claims that carry no AuthKit authority: another
// issuer's user, a resource access token (its authority is Permissions, for
// the resource server), a 2FA-enrollment-only token, or an unrecognized
// shape. A user's identity is bound to the session or device key its token
// was minted from (iam.InSession), so every permission check refuses it once
// that sign-in is revoked.
func boundIdentity(c Claims) (auth.Identity, bool) {
	if c.TwoFAEnrollment {
		return auth.Identity{}, false
	}
	var bound auth.Identity
	switch c.Kind {
	case TokenAPIKey:
		bound = iam.APIKeyIdentity(c.APIKeyID)
	case TokenUser:
		// A native token, including a device-key token. Another issuer's
		// user (Subject without UserID) has no AuthKit authority.
		if c.UserID != "" && !c.IsResourceToken() {
			bound = iam.InSession(iam.UserIdentity(c.UserID), c.session())
		}
	}
	id, ok := c.Identity()
	if _, authority := iam.StateOf(bound); !ok || !authority {
		return auth.Identity{}, false
	}
	id.Credential = id.Credential.WithState(bound.Credential.State())
	return id, true
}

// IdentityFromContext is the identity of the claims the middleware stored in
// ctx (Claims.Identity). Behind a gate it carries AuthKit's credential state,
// so operations accept it; claims SetClaims stored, or ones with no AuthKit
// authority, describe the request and grant nothing. VerifiedIdentity also
// requires the gate to be over a given authenticator.
func IdentityFromContext(ctx context.Context) (auth.Identity, bool) {
	v, ok := ctx.Value(claimsKey{}).(verified)
	return v.identity, ok && v.identity.Subject != ""
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
