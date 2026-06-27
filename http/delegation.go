package authhttp

import (
	jwtkit "github.com/open-rails/authkit/jwt"
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
