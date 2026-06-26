package authhttp

import (
	"context"
	authkit "github.com/open-rails/authkit"

	jwtkit "github.com/open-rails/authkit/jwt"

	"github.com/open-rails/authkit/embedded"
)

// DelegatedAccessTokenType is the canonical JOSE `typ` header value for a
// delegated access token.
const DelegatedAccessTokenType = jwtkit.DelegatedAccessTokenType

// AccessTokenType is the canonical JOSE `typ` header value for an AuthKit user
// access token.
const AccessTokenType = jwtkit.AccessTokenType

// RemoteApplicationAccessTokenType is the JOSE `typ` for a remote application
// access token. AuthKit resolves authority from the stored remote_application
// assignment, never from role claims in the token.
const RemoteApplicationAccessTokenType = jwtkit.RemoteApplicationAccessTokenType

// DelegatedAccessParams describes a delegated access token to mint. It is an
// alias for authkit.DelegatedAccessParams; the canonical definition (and the
// (*embedded.Client).MintDelegatedAccessToken mint method) live in package core so
// hosts can mint through the Service's internal signer without touching keys.
type DelegatedAccessParams = authkit.DelegatedAccessParams

// MintDelegatedAccessToken signs a canonical delegated access token with an
// explicit signer. It is a thin re-export of embedded.MintDelegatedAccessToken;
// embedders holding a *embedded.Client should prefer
// (*embedded.Client).MintDelegatedAccessToken so they never construct a signer.
func MintDelegatedAccessToken(ctx context.Context, signer jwtkit.Signer, p DelegatedAccessParams) (string, error) {
	return embedded.MintDelegatedAccessToken(ctx, signer, p)
}
