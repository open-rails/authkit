// Package tenancy carries only a trusted, resolved account target between the
// native client, HTTP dispatch and background operations. It grants no rights.
package tenancy

import (
	"context"
	"github.com/open-rails/authkit/iam"
)

type key struct{}

func With(ctx context.Context, id iam.TenantID) context.Context {
	return context.WithValue(ctx, key{}, id)
}
func From(ctx context.Context) (iam.TenantID, bool) {
	id, ok := ctx.Value(key{}).(iam.TenantID)
	return id, ok
}

type viewKey struct{}

// WithView is With for a tenant view (Client.ForTenant): its group reads and
// lifecycle stay in id's groups.
func WithView(ctx context.Context, id iam.TenantID) context.Context {
	return context.WithValue(With(ctx, id), viewKey{}, id)
}

// View is the tenant whose view ctx came from.
func View(ctx context.Context) (iam.TenantID, bool) {
	id, ok := ctx.Value(viewKey{}).(iam.TenantID)
	return id, ok
}
