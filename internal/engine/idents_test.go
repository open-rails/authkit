package engine

import (
	"context"

	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/ident"
)

// mustRole is the role `<persona>:<name>`.
func mustRole(text string) iam.Role {
	var r iam.Role
	if err := r.UnmarshalText([]byte(text)); err != nil {
		panic(err)
	}
	return r
}

// defineRole defines the custom role name holding perms.
func defineRole(e *Engine, ctx context.Context, a iam.Actor, ref iam.GroupRef, name string, perms []string) error {
	_, err := e.DefineGroupRole(ctx, a, ref, name, ident.Perms(perms)...)
	return err
}
