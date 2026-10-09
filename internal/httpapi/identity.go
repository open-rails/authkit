package httpapi

import (
	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/helpers/auth"
)

// state is AuthKit's credential state of id; the zero state, which grants
// nothing, when it has none.
func state(id auth.Identity) iam.CredentialState {
	s, _ := iam.StateOf(id)
	return s
}
