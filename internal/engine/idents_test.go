package engine

import "github.com/open-rails/authkit/iam"

// mustRole is the role `<persona>:<name>`.
func mustRole(text string) iam.Role {
	var r iam.Role
	if err := r.UnmarshalText([]byte(text)); err != nil {
		panic(err)
	}
	return r
}
