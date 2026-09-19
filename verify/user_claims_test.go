package verify

import (
	"context"
	"reflect"
	"testing"
	"time"
)

func TestUserClaimsFromContextRequiresLocalUser(t *testing.T) {
	for _, ctx := range []context.Context{nil, context.Background()} {
		if got, ok := UserClaimsFromContext(ctx); ok || !reflect.DeepEqual(got, UserClaimsData{}) {
			t.Fatalf("missing claims returned %+v, %v", got, ok)
		}
	}
	for name, cl := range map[string]Claims{
		"empty":            {},
		"external subject": {Issuer: "https://external.test", Subject: "user-1"},
		"api key":          {UserID: "user-1", TokenType: APIKeyPrincipalType},
		"application":      {UserID: "user-1", TokenType: RemoteApplicationTokenType},
		"delegated":        {UserID: "user-1", DelegatedSubject: "external-user"},
	} {
		t.Run(name, func(t *testing.T) {
			if got, ok := UserClaimsFromContext(SetClaims(context.Background(), cl)); ok || !reflect.DeepEqual(got, UserClaimsData{}) {
				t.Fatalf("non-local-user claims returned %+v, %v", got, ok)
			}
		})
	}
	got, ok := UserClaimsFromContext(SetClaims(context.Background(), Claims{UserID: "user-1"}))
	if !ok || !reflect.DeepEqual(got, UserClaimsData{UserID: "user-1"}) {
		t.Fatalf("absent optional claims must remain zero-valued: %+v, %v", got, ok)
	}
}

func TestUserClaimsFromContextPreservesFieldsAndCopiesSlices(t *testing.T) {
	cl := Claims{
		UserID: "user-1", Email: "user@example.com", EmailVerified: true,
		Username: "writer", SessionID: "session-1", Entitlements: []string{"premium"},
		AMR: []string{"pwd", "otp"}, ACR: "urn:authkit:loa:2",
		AuthTime: time.Unix(1700000000, 0), MFAEnrolled: true,
	}
	ctx := SetClaims(context.Background(), cl)
	got, ok := UserClaimsFromContext(ctx)
	want := UserClaimsData{
		UserID: cl.UserID, Email: cl.Email, EmailVerified: cl.EmailVerified,
		Username: cl.Username, SessionID: cl.SessionID, Entitlements: cl.Entitlements,
		AMR: cl.AMR, ACR: cl.ACR, AuthTime: cl.AuthTime, MFAEnrolled: cl.MFAEnrolled,
	}
	if !ok || !reflect.DeepEqual(got, want) {
		t.Fatalf("user projection = %+v, %v; want %+v", got, ok, want)
	}
	got.Entitlements[0], got.AMR[0] = "changed", "changed"
	stored, _ := ClaimsFromContext(ctx)
	if stored.Entitlements[0] != "premium" || stored.AMR[0] != "pwd" {
		t.Fatal("editing the projection mutated verified claims")
	}
	again, _ := UserClaimsFromContext(ctx)
	cl.Entitlements[0], cl.AMR[0] = "source changed", "source changed"
	if again.Entitlements[0] != "premium" || again.AMR[0] != "pwd" {
		t.Fatal("editing the source mutated an earlier projection")
	}
}
