package authkit

import "context"

// Authorizer is a cross-cutting consumer slice (#143): the "can this subject do
// X here" methods. Unlike the per-topic interfaces in client.go, it spans three
// of them (Groups for permission checks, Users for the live-user/ban gate, Roles
// for role resolution), so it is defined here as its own narrow view rather than
// mapping to one. doujins's request gate depends on it.
//
// Add a cross-cutting slice like this only when a real consumer signature needs
// one; the per-topic interfaces (Users, Tokens, Groups, ...) cover the rest.
type Authorizer interface {
	Can(ctx context.Context, subjectID, subjectKind, persona, instanceSlug, perm string) (bool, error)
	ListEffectivePermissions(ctx context.Context, subjectID, subjectKind, persona, instanceSlug string) ([]string, error)
	IsUserAllowed(ctx context.Context, userID string) (bool, error)
	ListRoleSlugsByUserErr(ctx context.Context, userID string) ([]string, error)
}
