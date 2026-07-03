package verify

import (
	"context"
	"crypto"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	authkit "github.com/open-rails/authkit"
	"github.com/open-rails/authkit/jwtkit"
)

// failEnricher implements Enricher but fails the test the moment ANY method is
// called. It pins the #215 contract: authenticating a valid native-user request
// performs ZERO enricher (DB) work — no per-request ban/deleted gate and no
// role/email/provider re-enrichment. A regression that reintroduces any
// per-request lookup on the common path trips one of these Fatals immediately.
type failEnricher struct{ t *testing.T }

func (e failEnricher) ResolveAPIKeyDetailed(context.Context, string, string) (authkit.ResolvedAPIKey, error) {
	e.t.Fatalf("ResolveAPIKeyDetailed called on the stateless native-user path")
	return authkit.ResolvedAPIKey{}, nil
}
func (e failEnricher) GetRemoteApplication(context.Context, string) (*authkit.RemoteApplication, error) {
	e.t.Fatalf("GetRemoteApplication called on the stateless native-user path")
	return nil, nil
}
func (e failEnricher) ListRemoteApplications(context.Context, bool) ([]authkit.RemoteApplication, error) {
	e.t.Fatalf("ListRemoteApplications called on the stateless native-user path")
	return nil, nil
}
func (e failEnricher) ResolveRemoteApplicationAuthority(context.Context, string) ([]string, error) {
	e.t.Fatalf("ResolveRemoteApplicationAuthority called on the stateless native-user path")
	return nil, nil
}
func (e failEnricher) ResolveRemoteAppAttributeDef(context.Context, string, string, int32) (*authkit.RemoteAppAttributeDef, error) {
	e.t.Fatalf("ResolveRemoteAppAttributeDef called on the stateless native-user path")
	return nil, nil
}
func (e failEnricher) GetProviderUsername(context.Context, string, string) (string, error) {
	e.t.Fatalf("GetProviderUsername called on the stateless native-user path")
	return "", nil
}
func (e failEnricher) ListRoleSlugsByUser(context.Context, string) []string {
	e.t.Fatalf("ListRoleSlugsByUser called on the stateless native-user path")
	return nil
}
func (e failEnricher) UsersByIDs(context.Context, []string) ([]authkit.UserRef, error) {
	e.t.Fatalf("UsersByIDs called on the stateless native-user path")
	return nil, nil
}
func (e failEnricher) IsUserAllowed(context.Context, string) (bool, error) {
	e.t.Fatalf("IsUserAllowed called on the stateless native-user path")
	return false, nil
}

func mintStatelessAccess(t *testing.T, signer jwtkit.Signer, iss, aud, sub string) string {
	t.Helper()
	hs, ok := any(signer).(jwtkit.HeaderSigner)
	if !ok {
		t.Fatal("test signer must support JOSE headers")
	}
	now := time.Now()
	tok, err := hs.SignWithHeaders(context.Background(), map[string]any{
		"iss": iss,
		"aud": aud,
		"sub": sub,
		"iat": now.Add(-time.Minute).Unix(),
		"exp": now.Add(time.Hour).Unix(),
	}, map[string]any{"typ": AccessTokenType})
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	return tok
}

// TestAuthenticatedRequestPath_NoDBLookups is the #215 integration guard: a
// valid native-user request is authenticated end to end WITH an enricher wired
// in, yet the enricher is never touched. If the ban gate or role/email/provider
// enrichment is ever reintroduced on the common request path, failEnricher fails
// the test.
func TestAuthenticatedRequestPath_NoDBLookups(t *testing.T) {
	signer, err := jwtkit.NewRSASigner(2048, "test-kid")
	if err != nil {
		t.Fatalf("new signer: %v", err)
	}
	const iss = "https://issuer.example"
	const aud = "my-api"

	// WithService wires the FAILING enricher: any per-request DB call trips it.
	v := NewVerifier(WithAlgorithms("RS256")).WithService(failEnricher{t})
	if err := v.AddIssuer(iss, []string{aud}, IssuerOptions{
		RawKeys: map[string]crypto.PublicKey{signer.KID(): signer.PublicKey()},
		IsLocal: true,
	}); err != nil {
		t.Fatalf("add issuer: %v", err)
	}

	tok := mintStatelessAccess(t, signer, iss, aud, "user-123")

	// Direct entry point: VerifyRequest succeeds without touching the enricher.
	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	cl, err := v.VerifyRequest(req)
	if err != nil {
		t.Fatalf("VerifyRequest: %v", err)
	}
	if cl.UserID != "user-123" {
		t.Fatalf("UserID = %q, want user-123", cl.UserID)
	}

	// And through the Required middleware, end to end.
	var sawUser string
	h := Required(v)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, ok := ClaimsFromContext(r.Context())
		if !ok {
			t.Error("claims missing from request context")
		}
		sawUser = c.UserID
		w.WriteHeader(http.StatusOK)
	}))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("protected route status = %d, want 200", rec.Code)
	}
	if sawUser != "user-123" {
		t.Fatalf("handler saw UserID = %q, want user-123", sawUser)
	}
}
