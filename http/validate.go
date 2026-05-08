package authhttp

import core "github.com/open-rails/authkit/core"

func validateUsername(username string) error {
	return core.ValidateUsername(username)
}
