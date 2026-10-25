package authkit

import (
	"context"
	"errors"

	"github.com/open-rails/authkit/auth"
	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/engine"
	"github.com/open-rails/authkit/internal/tenancy"
)

// CreateTenant explicitly provisions one canonical tenant. It creates no
// account, role assignment, credential, or application. Native calls are a
// trusted host interface; HTTP provisioning must separately authorize root.
func (a *Client) CreateTenant(ctx context.Context, tenant iam.Tenant) error {
	return a.engine.CreateTenant(ctx, tenant)
}

// ForTenant selects an existing tenant for native account operations and HTTP
// dispatch. It borrows this client's engine, pools, keys and worker lifecycle.
// Selecting a tenant does not grant the caller any authority in it.
func (a *Client) ForTenant(ctx context.Context, id iam.TenantID) (*Client, error) {
	if a == nil || a.engine == nil {
		return nil, errors.New("authkit: tenant view requires a client")
	}
	if _, err := a.engine.Tenant(ctx, id); err != nil {
		return nil, err
	}
	return &Client{ops: a.ops, engine: a.engine, http: a.http, mount: a.mount,
		cfg: a.cfg, deps: a.deps, tenantID: id, borrowed: true}, nil
}

// ResolveTenantActor returns verified, live source-account ownership. It is
// deliberately independent of ForTenant's target and performs no target grant.
// A retained native credential must still be within its original verified
// lifetime; resolving it does not verify the request or spend a sender proof again.
// Native Identity-preserving wrappers retain this lifetime in sealed state.
// Resource credentials require the original verified value; their source-only
// provenance is deliberately not native IAM permission authority.
func (a *Client) ResolveTenantActor(ctx context.Context, verified auth.Verified) (iam.TenantActor, error) {
	return a.engine.ResolveTenantActor(ctx, verified)
}

func (a *Client) operationContext(ctx context.Context) context.Context {
	id := a.tenantID
	if id.IsZero() {
		if _, ok := tenancy.From(ctx); ok {
			return ctx
		}
		id = a.cfg.DefaultTenantID
	}
	if !id.IsZero() {
		return engine.WithTenant(ctx, id)
	}
	return ctx
}
