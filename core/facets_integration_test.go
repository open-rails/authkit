package core

import (
	"context"
	"fmt"
	"slices"
	"testing"
	"time"
)

func TestServiceFacetsBackedByPostgres(t *testing.T) {
	pool := testPG(t)
	ctx := context.Background()
	slug := fmt.Sprintf("facet-it-%d", time.Now().UnixNano())

	_, _ = pool.Exec(ctx, `DELETE FROM profiles.orgs WHERE slug=$1`, slug)
	t.Cleanup(func() { _, _ = pool.Exec(context.Background(), `DELETE FROM profiles.orgs WHERE slug=$1`, slug) })

	svc := NewService(Options{
		Issuer:       "https://test",
		APIKeyPrefix: "facet",
		Permissions:  []PermissionDef{{Name: "repo:read"}},
	}, Keyset{}, WithPostgres(pool))

	org, err := svc.Orgs().CreateOrg(ctx, slug)
	if err != nil {
		t.Fatalf("Orgs().CreateOrg: %v", err)
	}
	if org.Slug != slug {
		t.Fatalf("org slug = %q, want %q", org.Slug, slug)
	}

	if err := svc.Roles().DefineRole(ctx, slug, "reader"); err != nil {
		t.Fatalf("Roles().DefineRole: %v", err)
	}
	if err := svc.Roles().SetRolePermissions(ctx, slug, "reader", []string{"repo:read"}); err != nil {
		t.Fatalf("Roles().SetRolePermissions: %v", err)
	}
	perms, err := svc.Roles().EffectiveRolePermissions(ctx, slug, "reader")
	if err != nil {
		t.Fatalf("Roles().EffectiveRolePermissions: %v", err)
	}
	if !slices.Contains(perms, "repo:read") {
		t.Fatalf("permissions = %v, want repo:read", perms)
	}

	key, plaintext, err := svc.APIKeys().MintAPIKeyWithOptions(ctx, slug, APIKeyMintOptions{
		Name: "facet integration",
		Role: "reader",
	})
	if err != nil {
		t.Fatalf("APIKeys().MintAPIKeyWithOptions: %v", err)
	}
	if key.Role != "reader" || plaintext == "" {
		t.Fatalf("bad key result: key=%+v plaintext empty=%v", key, plaintext == "")
	}

	keyID, secret, ok := ParseAPIKey("facet", plaintext)
	if !ok {
		t.Fatalf("ParseAPIKey ok=false for %q", plaintext)
	}
	resolved, err := svc.APIKeys().ResolveAPIKeyWithResources(ctx, keyID, secret)
	if err != nil {
		t.Fatalf("APIKeys().ResolveAPIKeyWithResources: %v", err)
	}
	if resolved.OrgSlug != slug || !slices.Contains(resolved.Permissions, "repo:read") {
		t.Fatalf("resolved = %+v, want org %q with repo:read", resolved, slug)
	}
}
