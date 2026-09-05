package authcore

import (
	"context"
	"strconv"
	"testing"
	"time"

	"github.com/open-rails/authkit/internal/testdb"
)

// The step-up gate and method list read provider links through the engine,
// not through raw SQL in the transport: HasProviderLink is exact on
// (issuer, slug) and ProviderSlugs is distinct.
func TestProviderLinkQueries(t *testing.T) {
	svc := mustNewService(t, Config{Token: TokenConfig{Issuer: "https://test"}}, Keyset{}, WithPostgres(testdb.Pool(t)))
	ctx := context.Background()
	suffix := strconv.FormatInt(time.Now().UnixNano(), 36)
	u, err := svc.CreateUser(ctx, "links"+suffix+"@example.com", "links"+suffix)
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	t.Cleanup(func() { _ = svc.AdminDeleteUser(ctx, u.ID) })

	has, err := svc.HasProviderLink(ctx, u.ID, "https://accounts.example", "google")
	if err != nil || has {
		t.Fatalf("HasProviderLink before link = %v, %v; want false, nil", has, err)
	}
	if err := svc.LinkProviderByIssuer(ctx, u.ID, "https://accounts.example", "google", "subject-"+suffix, nil); err != nil {
		t.Fatalf("LinkProviderByIssuer: %v", err)
	}
	has, err = svc.HasProviderLink(ctx, u.ID, "https://accounts.example", "google")
	if err != nil || !has {
		t.Fatalf("HasProviderLink after link = %v, %v; want true, nil", has, err)
	}
	if has, _ := svc.HasProviderLink(ctx, u.ID, "https://accounts.example", "github"); has {
		t.Fatal("HasProviderLink must be exact on the provider slug")
	}
	if has, _ := svc.HasProviderLink(ctx, u.ID, "https://other.example", "google"); has {
		t.Fatal("HasProviderLink must be exact on the issuer")
	}
	slugs, err := svc.ProviderSlugs(ctx, u.ID)
	if err != nil || len(slugs) != 1 || slugs[0] != "google" {
		t.Fatalf("ProviderSlugs = %v, %v; want [google]", slugs, err)
	}
}
