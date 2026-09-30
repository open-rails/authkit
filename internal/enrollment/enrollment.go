// Package enrollment marks requests to AuthKit's 2FA-enrollment routes, the
// only ones a 2FA-enrollment-only token reaches and the only ones a user a
// Required 2FA policy has yet to enroll may use. Only AuthKit's route table
// marks a request, so no host code can widen either.
package enrollment

import "context"

type key struct{}

// Route marks ctx as an enrollment route's.
func Route(ctx context.Context) context.Context { return context.WithValue(ctx, key{}, true) }

// IsRoute reports whether ctx is an enrollment route's.
func IsRoute(ctx context.Context) bool {
	v, _ := ctx.Value(key{}).(bool)
	return v
}
