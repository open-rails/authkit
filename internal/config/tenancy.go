package config

import (
	"fmt"

	"github.com/open-rails/authkit/iam"
)

// tenantPending reports a single-tenant deployment whose tenant New reads
// from the database: settings that name no tenant get it then.
func (c *Config) tenantPending() bool {
	return c.Tenancy == TenancySingle && c.DefaultTenantID.IsZero()
}

// BindDefaultTenant makes id the default tenant of a normalized Config, as
// New does with a single-tenant database's sole tenant: unscoped operations,
// and the provisioning targets and OAuth clients that name no tenant, act in
// it. Single-tenant, nothing may name another.
func BindDefaultTenant(c *Config, id iam.TenantID) error {
	if id.IsZero() {
		return iam.ErrTenantRequired
	}
	if !c.DefaultTenantID.IsZero() && c.DefaultTenantID != id {
		return fmt.Errorf("authkit: DefaultTenantID %s is not the database's tenant %s", c.DefaultTenantID, id)
	}
	c.DefaultTenantID = id
	var named []iam.TenantID
	bind := func(t *iam.TenantID) {
		if t.IsZero() {
			*t = id
		}
		named = append(named, *t)
	}
	for i := range c.Provisioning.Targets {
		bind(&c.Provisioning.Targets[i].TenantID)
	}
	for i := range c.AuthorizationServer.Clients {
		bind(&c.AuthorizationServer.Clients[i].TenantID)
	}
	if c.Tenancy == TenancySingle {
		for _, t := range named {
			if t != id {
				return fmt.Errorf("authkit: configuration names tenant %s, but this single-tenant deployment's tenant is %s: %w", t, id, iam.ErrSingleTenant)
			}
		}
	}
	return nil
}
