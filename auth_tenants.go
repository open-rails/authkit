package authkit

import (
	"context"
	"errors"
	"net/http"

	"github.com/open-rails/authkit/auth"
	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/engine"
	"github.com/open-rails/authkit/internal/errmodel"
	"github.com/open-rails/authkit/internal/tenancy"
)

// CreateTenant explicitly provisions one canonical tenant under its ID and
// name (Slug, normalized by iam.NormalizeTenantSlug). It creates no account,
// role assignment, credential, or application. Repeating it with the same ID
// and name is safe; the ID under another name is iam.ErrTenantConflict, and a
// name another tenant holds, now or as an unexpired former name, is
// iam.ErrTenantNameTaken. Native calls are a trusted host interface; HTTP
// provisioning requires root:tenants:manage.
func (a *Client) CreateTenant(ctx context.Context, tenant iam.Tenant) error {
	return a.engine.CreateTenant(ctx, tenant)
}

// Tenant reads one tenant by its ID.
func (a *Client) Tenant(ctx context.Context, id iam.TenantID) (iam.Tenant, error) {
	return a.engine.Tenant(ctx, id)
}

// RenameTenant gives a tenant a new name. Its ID, and so its accounts,
// tokens, keys and grants, are unchanged. The old name keeps resolving to it,
// and no other tenant may claim it, as Config.Tenants.FormerNames says; the
// tenant may take a former name of its own back. A name another tenant holds
// is iam.ErrTenantNameTaken.
func (a *Client) RenameTenant(ctx context.Context, id iam.TenantID, slug string) (iam.Tenant, error) {
	return a.engine.RenameTenant(ctx, id, slug)
}

// ResolveTenant finds the tenant a name belongs to: its current name, or a
// former name that still forwards. The returned Slug is the current name. An
// unknown name is iam.ErrTenantNotFound.
func (a *Client) ResolveTenant(ctx context.Context, slug string) (iam.Tenant, error) {
	return a.engine.ResolveTenant(ctx, slug)
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

// requestContext selects once, outside the mount's proof-consuming guards.
func (a *Client) requestContext(r *http.Request) (context.Context, error) {
	ctx := a.operationContext(r.Context())
	if a.deps.RequestTenant == nil {
		return ctx, nil
	}
	id, err := a.deps.RequestTenant(r)
	if err == nil && !id.IsZero() {
		if !a.tenantID.IsZero() && id != a.tenantID {
			err = iam.ErrTenantMismatch
		} else if _, err = a.engine.Tenant(ctx, id); err == nil {
			ctx = engine.WithTenant(ctx, id)
		}
	}
	switch {
	case errors.Is(err, iam.ErrTenantNotFound):
		err = errmodel.E(errmodel.CodeNotFound)
	case errors.Is(err, iam.ErrTenantMismatch), errors.Is(err, auth.ErrForbidden):
		err = errmodel.E(errmodel.CodeForbidden)
	}
	return ctx, err
}

// TenantFromContext reports the account directory selected by AuthKit's trusted
// native tenant view or HTTP dispatch. Host callbacks use it to select their
// policy for that exact operation target. It is not the caller's identity and
// grants no permission. An unscoped context returns false.
func TenantFromContext(ctx context.Context) (iam.TenantID, bool) {
	return tenancy.From(ctx)
}
