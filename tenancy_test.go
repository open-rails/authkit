package authkit_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/open-rails/authkit"
	"github.com/open-rails/authkit/iam"
)

// A single-tenant Client refuses tenant management before any database
// work; the multi-tenant opt-in is named in the refusal.
func TestSingleTenantRefusesOtherTenants(t *testing.T) {
	cfg := authkit.Config{Token: authkit.TokenConfig{Issuer: "https://auth.example.com", IssuedAudiences: []string{"app"}}, Keys: authkit.KeysConfig{VerifyOnly: true}}
	client, err := authkit.New(context.Background(), cfg, authkit.Deps{})
	noErr(t, err)
	t.Cleanup(func() { _ = client.Close(context.Background()) })
	err = client.CreateTenant(t.Context(), iam.Tenant{ID: iam.NewTenantID(), Slug: "another"})
	if !errors.Is(err, iam.ErrSingleTenant) || !strings.Contains(err.Error(), "TenancyMulti") {
		t.Fatalf("CreateTenant = %v, want ErrSingleTenant naming TenancyMulti", err)
	}
	if _, err := client.ForTenant(t.Context(), iam.NewTenantID()); !errors.Is(err, iam.ErrSingleTenant) {
		t.Fatalf("ForTenant(another) = %v, want ErrSingleTenant", err)
	}
}
