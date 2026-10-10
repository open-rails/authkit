package authkit

import (
	"net/http"

	"github.com/open-rails/helpers/auth"
)

// authenticateResource is Authenticate for an access token (at+jwt) minted
// for Config.Resource.ID, by this deployment or one of its trusted issuers.
func (a *Client) authenticateResource(r *http.Request) (auth.Verified, error) {
	return a.engine.AuthenticateResource(r)
}
