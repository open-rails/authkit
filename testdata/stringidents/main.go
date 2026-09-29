// Package main is host code that names roles, permissions and personas with
// strings. It must not compile: TestStringIdentifiersDoNotCompile builds it.
package main

import (
	"context"

	"github.com/open-rails/authkit"
	"github.com/open-rails/authkit/iam"
)

func main() {
	var auth *authkit.Auth
	ctx := context.Background()
	_, _ = auth.EnsureUserRole(ctx, iam.UserByEmail("admin@example.com"), iam.RootGroup(), "admin") // want error
	_, _ = auth.Can(ctx, iam.UserActor("user"), iam.RootGroup(), "root:users:ban")                  // want error
	_, _ = auth.CreateGroup(ctx, iam.NewGroup{Persona: "channel"})                                  // want error
	_ = auth.RequirePermission(iam.RootGroup(), "channel:posts:edit")                               // want error
	_ = iam.Role("admin")                                                                           // want error
	var perm iam.Perm = "channel:posts:edit"                                                        // want error
	_ = perm
}
