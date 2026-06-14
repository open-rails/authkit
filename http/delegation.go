package authhttp

import (
	"context"

	jwtkit "github.com/open-rails/authkit/jwt"

	core "github.com/open-rails/authkit/core"
)

// DelegatedAccessTokenType is the canonical JOSE `typ` header value for a
// delegated service token.
const DelegatedAccessTokenType = jwtkit.DelegatedAccessTokenType

// AccessTokenType is the canonical JOSE `typ` header value for an AuthKit
// service token.
const AccessTokenType = jwtkit.AccessTokenType

// RemoteApplicationAccessTokenType is the JOSE `typ` for a JWKS principal's
// SELF-token (#76): a remote_application signs a JWT whose subject is itself,
// and AuthKit grants it the STORED authority WE ASSIGNED (its tenant roles +
// direct permissions), never what the token self-claims.
const RemoteApplicationAccessTokenType = jwtkit.RemoteApplicationAccessTokenType

// DelegatedAccessParams describes a delegated service token to mint. It is an
// alias for core.DelegatedAccessParams; the canonical definition (and the
// (*core.Service).MintDelegatedAccessToken mint method) live in package core so
// hosts can mint through the Service's internal signer without touching keys.
type DelegatedAccessParams = core.DelegatedAccessParams

// MintDelegatedAccessToken signs a canonical delegated service token with an
// explicit signer. It is a thin re-export of core.MintDelegatedAccessToken;
// embedders holding a *core.Service should prefer
// (*core.Service).MintDelegatedAccessToken so they never construct a signer.
func MintDelegatedAccessToken(ctx context.Context, signer jwtkit.Signer, p DelegatedAccessParams) (string, error) {
	return core.MintDelegatedAccessToken(ctx, signer, p)
}
