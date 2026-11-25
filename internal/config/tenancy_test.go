package config

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/notify"
)

func tenancyConfig(tenancy Tenancy, producers ...NotificationProducer) Config {
	return Config{
		Tenancy:       tenancy,
		Issuer:        "https://auth.example.com",
		Notifications: &NotificationsConfig{Producers: producers},
	}
}

func producer(name string, tenant iam.TenantID) NotificationProducer {
	return NotificationProducer{Name: name, TenantID: tenant, Visibility: notify.VisibilityTenant, Origin: notify.OriginScope{System: "billing", Scope: "invoices"}}
}

func TestTenancyIsSingleUnlessMulti(t *testing.T) {
	if (Config{}).Tenancy != TenancySingle || TenancySingle.String() != "single" || TenancyMulti.String() != "multi" {
		t.Fatal("the zero Config is not single-tenant")
	}
	if _, _, err := Normalize(tenancyConfig(Tenancy(7)), Deps{}); err == nil || !strings.Contains(err.Error(), "invalid Tenancy") {
		t.Fatalf("Normalize = %v, want an unknown Tenancy refused", err)
	}
}

// A single-tenant deployment's tenant is the database's, known once New has
// migrated: settings naming no tenant wait for it. Multi-tenant they need
// one, or DefaultTenantID.
func TestUnnamedTenantsWaitForTheSoleTenant(t *testing.T) {
	if _, _, err := Normalize(tenancyConfig(TenancySingle, producer("invoices", iam.TenantID{})), Deps{}); err != nil {
		t.Fatalf("single-tenant: %v", err)
	}
	if _, _, err := Normalize(tenancyConfig(TenancyMulti, producer("invoices", iam.TenantID{})), Deps{}); err == nil || !strings.Contains(err.Error(), "needs a tenant") {
		t.Fatalf("multi-tenant without a default = %v, want a producer refused", err)
	}
	multi := tenancyConfig(TenancyMulti, producer("invoices", iam.TenantID{}))
	multi.DefaultTenantID = iam.NewTenantID()
	norm, _, err := Normalize(multi, Deps{})
	if err != nil || norm.Notifications.Producers[0].TenantID != multi.DefaultTenantID {
		t.Fatalf("multi-tenant default not applied: %v", err)
	}
}

func TestBindDefaultTenant(t *testing.T) {
	sole, other := iam.NewTenantID(), iam.NewTenantID()
	bind := func(c Config, id iam.TenantID) (Config, error) {
		t.Helper()
		norm, _, err := Normalize(c, Deps{})
		if err != nil {
			t.Fatal(err)
		}
		norm.Provisioning.Targets = []ProvisioningTarget{{Name: "billing"}}
		norm.AuthorizationServer.Clients = []OAuthClientConfig{{ID: "scim"}}
		return norm, BindDefaultTenant(&norm, id)
	}

	norm, err := bind(tenancyConfig(TenancySingle, producer("invoices", iam.TenantID{})), sole)
	if err != nil || norm.DefaultTenantID != sole || norm.Notifications.Producers[0].TenantID != sole ||
		norm.Provisioning.Targets[0].TenantID != sole || norm.AuthorizationServer.Clients[0].TenantID != sole {
		t.Fatalf("unnamed tenants not bound to the sole tenant: %v", err)
	}

	explicit := tenancyConfig(TenancySingle)
	explicit.DefaultTenantID = other
	if _, err := bind(explicit, sole); err == nil || !strings.Contains(err.Error(), "is not the database's tenant") {
		t.Fatalf("a DefaultTenantID other than the sole tenant = %v", err)
	}

	if _, err := bind(tenancyConfig(TenancySingle, producer("invoices", other)), sole); !errors.Is(err, iam.ErrSingleTenant) {
		t.Fatalf("single-tenant producer of another tenant = %v, want ErrSingleTenant", err)
	}
	if _, err := bind(tenancyConfig(TenancyMulti, producer("invoices", other)), sole); err != nil {
		t.Fatalf("multi-tenant producer of another tenant: %v", err)
	}

	if _, err := bind(tenancyConfig(TenancySingle, producer("invoices", iam.TenantID{}), producer("invoices", sole)), sole); err == nil || !strings.Contains(err.Error(), "unique producer name") {
		t.Fatalf("two producers of one name once bound = %v", err)
	}
}

func TestNewTenantIDIsTimeOrderedUUIDv7(t *testing.T) {
	before := time.Now().UnixMilli()
	first := iam.NewTenantID()
	time.Sleep(2 * time.Millisecond)
	second := iam.NewTenantID()
	for _, id := range []iam.TenantID{first, second} {
		if id[6]>>4 != 7 || id[8]>>6 != 0b10 {
			t.Fatalf("%s is not a UUIDv7 with the RFC variant", id)
		}
		ms := int64(0)
		for _, b := range id[:6] {
			ms = ms<<8 | int64(b)
		}
		if ms < before || ms > time.Now().UnixMilli() {
			t.Fatalf("%s carries %d, not the time it was made", id, ms)
		}
		if parsed, err := iam.ParseTenantID(id.String()); err != nil || parsed != id {
			t.Fatalf("%s does not round-trip: %v", id, err)
		}
	}
	if first.String() >= second.String() {
		t.Fatalf("%s sorts after the later %s", first, second)
	}
}
