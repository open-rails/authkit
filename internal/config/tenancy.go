package config

import (
	"fmt"
	"maps"
	"slices"

	"github.com/open-rails/authkit/iam"
)

// tenantPending reports a single-tenant deployment whose tenant New reads
// from the database: settings that name no tenant get it then.
func (c *Config) tenantPending() bool {
	return c.Tenancy == TenancySingle && c.DefaultTenantID.IsZero()
}

// BindDefaultTenant makes id the default tenant of a normalized Config, as
// New does with a single-tenant database's sole tenant: unscoped operations,
// and the provisioning targets, OAuth clients and notification producers that
// name no tenant, act in it. Single-tenant, nothing may name another.
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
	if n := c.Notifications; n != nil {
		producers := map[string]bool{}
		for i := range n.Producers {
			p := &n.Producers[i]
			bind(&p.TenantID)
			key := p.TenantID.String() + ":" + p.Name
			if producers[key] {
				return fmt.Errorf("authkit notifications: unique producer name per tenant required: %q", p.Name)
			}
			producers[key] = true
		}
		for _, tenant := range slices.Sorted(maps.Keys(n.Scopes)) {
			parsed, err := iam.ParseTenantID(tenant)
			if err != nil {
				return err
			}
			named = append(named, parsed)
		}
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
