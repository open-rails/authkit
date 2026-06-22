package core

import "testing"

func TestServiceFacetsReturnSameService(t *testing.T) {
	svc := NewService(Options{Issuer: "https://issuer.example"}, Keyset{})

	if svc.Users().svc != svc ||
		svc.Roles().svc != svc ||
		svc.APIKeys().svc != svc ||
		svc.Tokens().svc != svc ||
		svc.TwoFactor().svc != svc ||
		svc.Sessions().svc != svc ||
		svc.Identity().svc != svc ||
		svc.Bootstrap().svc != svc {
		t.Fatal("facet did not wrap original service")
	}

	if got := svc.Users().DeriveUsername("person@example.com"); got != "person" {
		t.Fatalf("facet delegate DeriveUsername() = %q", got)
	}
}
