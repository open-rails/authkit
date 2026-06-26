package authhttp

import "github.com/open-rails/authkit/embedded"

func validateUsername(username string) error {
	return embedded.ValidateUsername(username)
}
