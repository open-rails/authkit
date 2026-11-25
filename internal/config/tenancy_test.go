package config

import (
	"strings"
	"testing"
	"time"

	"github.com/open-rails/authkit/iam"
)

func tenancyConfig(tenancy Tenancy) Config {
	return Config{Tenancy: tenancy, Issuer: "https://auth.example.com"}
}

// AK-J02-C08 to C11 prove DefaultTenantID single-tenant only; the per-object
// tenant IDs and an unknown Tenancy are refused here.
func TestSingleTenantNamesNoTenant(t *testing.T) {
	id := iam.NewTenantID()
	for name, edit := range map[string]func(*Config){
		"AuthorizationServer.Clients[0].TenantID": func(c *Config) { c.AuthorizationServer.Clients = []OAuthClientConfig{{ID: "scim", TenantID: id}} },
		"Provisioning[0].TenantID":                func(c *Config) { c.Provisioning = []ProvisioningTarget{{Name: "billing", TenantID: id}} },
	} {
		single := tenancyConfig(TenancySingle)
		edit(&single)
		if _, _, err := Normalize(single, Deps{}); err == nil || !strings.Contains(err.Error(), name+" is multi-tenant only") {
			t.Fatalf("single-tenant %s = %v, want refused", name, err)
		}
	}
	if _, _, err := Normalize(tenancyConfig(Tenancy(7)), Deps{}); err == nil || !strings.Contains(err.Error(), "invalid Tenancy") {
		t.Fatalf("Normalize = %v, want an unknown Tenancy refused", err)
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
