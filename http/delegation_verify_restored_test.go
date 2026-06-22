package authhttp

import (
	"context"
	"crypto"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	jwt "github.com/golang-jwt/jwt/v5"
	"github.com/open-rails/authkit/authbase"
	jwtkit "github.com/open-rails/authkit/jwt"
)

// Restores coverage from the deleted delegation_test.go / delegation_issuer_only_test.go /
// delegated_roles_test.go after the org→permission-group hard cut (#111). The old
// helper newDelegatedTestVerifier was removed (it referenced WithOrgMode +
// ResolveRemoteApplicationAuthority/OrgMembership). The current
// RemoteApplicationSource interface needs only List/Get, so we define a local
// in-memory source here and verify the issuer-only delegated-token contract that
// survives the cut. No org/platform claims are asserted (those fields are gone).

// memRemoteAppSource is a minimal in-memory RemoteApplicationSource for the
// verify layer (List + Get only — the surviving interface shape).
type memRemoteAppSource struct {
	apps []authbase.RemoteApplication
}

func (m *memRemoteAppSource) ListRemoteApplications(_ context.Context, enabledOnly bool) ([]authbase.RemoteApplication, error) {
	if !enabledOnly {
		return m.apps, nil
	}
	var out []authbase.RemoteApplication
	for _, a := range m.apps {
		if a.Enabled {
			out = append(out, a)
		}
	}
	return out, nil
}

func (m *memRemoteAppSource) GetRemoteApplication(_ context.Context, issuer string) (*authbase.RemoteApplication, error) {
	for i := range m.apps {
		if m.apps[i].Issuer == issuer {
			a := m.apps[i]
			return &a, nil
		}
	}
	return nil, errors.New("not_found")
}

// newRestoredDelegatedVerifier builds a Verifier trusting a single remote
// application (jwks-less; raw key seeded) — the replacement for the removed
// newDelegatedTestVerifier. It carries NO org mode.
func newRestoredDelegatedVerifier(t *testing.T, signer *jwtkit.RSASigner, iss string, aud []string) *Verifier {
	t.Helper()
	v := NewVerifier()
	v.SetRemoteApplicationSource(&memRemoteAppSource{apps: []authbase.RemoteApplication{{
		ID:      "remote-app-1",
		Slug:    "remote-app",
		Issuer:  iss,
		Enabled: true,
	}}})
	if err := v.AddIssuer(iss, aud, IssuerOptions{
		RawKeys: map[string]crypto.PublicKey{signer.KID(): signer.PublicKey()},
	}); err != nil {
		t.Fatalf("AddIssuer: %v", err)
	}
	return v
}

func TestRestoredMintAndVerifyDelegatedAccessTokenBasic(t *testing.T) {
	signer, err := jwtkit.NewRSASigner(2048, "host-kid")
	if err != nil {
		t.Fatal(err)
	}
	iss := "https://cozy.example"
	aud := []string{"tensorhub"}
	tok, err := MintDelegatedAccessToken(context.Background(), signer, DelegatedAccessParams{
		Issuer:           iss,
		Audiences:        aud,
		DelegatedSubject: "user-123",
		Attributes:       map[string]any{"tier": "cozy_free"},
		TTL:              time.Minute,
	})
	if err != nil {
		t.Fatalf("mint: %v", err)
	}

	cl, err := newRestoredDelegatedVerifier(t, signer, iss, aud).Verify(tok)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if cl.UserID != "" {
		t.Fatalf("expected empty UserID (no sub), got %q", cl.UserID)
	}
	if !cl.IsDelegated() {
		t.Fatal("expected IsDelegated")
	}
	dp, ok := cl.Delegated()
	if !ok {
		t.Fatal("Delegated() returned !ok")
	}
	if dp.DelegatedSubject != "user-123" || dp.UserTier != "cozy_free" {
		t.Fatalf("principal=%+v", dp)
	}
}

func TestRestoredVerifyRejectsBothSubAndDelegatedSub(t *testing.T) {
	signer, _ := jwtkit.NewRSASigner(2048, "host-kid")
	iss := "https://cozy.example"
	now := time.Now()
	tok, err := signer.Sign(context.Background(), jwt.MapClaims{
		"iss":           iss,
		"aud":           []string{"tensorhub"},
		"iat":           now.Unix(),
		"exp":           now.Add(time.Minute).Unix(),
		"sub":           "local-1",
		"delegated_sub": "ext-1",
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = newRestoredDelegatedVerifier(t, signer, iss, []string{"tensorhub"}).Verify(tok)
	if err == nil || err.Error() != "conflicting_subject" {
		t.Fatalf("expected conflicting_subject, got %v", err)
	}
}

func TestRestoredMintRequiresDelegatedSubject(t *testing.T) {
	signer, _ := jwtkit.NewRSASigner(2048, "k")
	if _, err := MintDelegatedAccessToken(context.Background(), signer, DelegatedAccessParams{Issuer: "x"}); err == nil {
		t.Fatal("expected error for missing delegated_sub")
	}
}

func TestRestoredNativeTokenIsNotDelegated(t *testing.T) {
	signer, _ := jwtkit.NewRSASigner(2048, "k")
	iss := "https://cozy.example"
	now := time.Now()
	tok, _ := signer.SignWithHeaders(context.Background(), jwt.MapClaims{
		"iss": iss,
		"aud": []string{"tensorhub"},
		"iat": now.Unix(),
		"exp": now.Add(time.Minute).Unix(),
		"sub": "local-1",
	}, map[string]any{"typ": AccessTokenType})
	cl, err := newRestoredDelegatedVerifier(t, signer, iss, []string{"tensorhub"}).Verify(tok)
	if err != nil {
		t.Fatal(err)
	}
	if cl.IsDelegated() {
		t.Fatal("native token should not be delegated")
	}
	if cl.UserID != "local-1" {
		t.Fatalf("UserID=%q", cl.UserID)
	}
}

func TestRestoredVerifyRejectsAccessTokenWithoutAccessTyp(t *testing.T) {
	signer, _ := jwtkit.NewRSASigner(2048, "k")
	iss := "https://cozy.example"
	now := time.Now()
	tok, _ := signer.Sign(context.Background(), jwt.MapClaims{
		"iss": iss,
		"aud": []string{"tensorhub"},
		"iat": now.Unix(),
		"exp": now.Add(time.Minute).Unix(),
		"sub": "local-1",
	})
	_, err := newRestoredDelegatedVerifier(t, signer, iss, []string{"tensorhub"}).Verify(tok)
	if err == nil || err.Error() != "access_token_wrong_typ" {
		t.Fatalf("expected access_token_wrong_typ, got %v", err)
	}
}

func TestRestoredVerifyRejectsDelegatedSubWithoutDelegatedTyp(t *testing.T) {
	signer, _ := jwtkit.NewRSASigner(2048, "k")
	iss := "https://cozy.example"
	now := time.Now()
	tok, _ := signer.SignWithHeaders(context.Background(), jwt.MapClaims{
		"iss":           iss,
		"aud":           []string{"tensorhub"},
		"iat":           now.Unix(),
		"exp":           now.Add(time.Minute).Unix(),
		"delegated_sub": "ext-1",
	}, map[string]any{"typ": AccessTokenType})
	_, err := newRestoredDelegatedVerifier(t, signer, iss, []string{"tensorhub"}).Verify(tok)
	if err == nil || err.Error() != "delegated_access_wrong_typ" {
		t.Fatalf("expected delegated_access_wrong_typ, got %v", err)
	}
}

// TestRestoredIssuerOnlyDelegatedToken: the canonical mint carries delegated_sub
// and NEITHER org claim (org/org_id); verification via VerifyDelegatedAccess
// accepts it and the principal's identity rides on the validated issuer. This is
// the surviving form of the deleted delegation_issuer_only_test.go contract.
func TestRestoredIssuerOnlyDelegatedToken(t *testing.T) {
	signer, err := jwtkit.NewRSASigner(2048, "host-kid")
	if err != nil {
		t.Fatal(err)
	}
	iss := "https://doujins.example"
	aud := []string{"openrails"}
	tok, err := MintDelegatedAccessToken(context.Background(), signer, DelegatedAccessParams{
		Issuer:           iss,
		Audiences:        aud,
		DelegatedSubject: "user-123",
		Permissions:      []string{"openrails:self:billing:read"},
		TTL:              time.Minute,
	})
	if err != nil {
		t.Fatalf("mint: %v", err)
	}

	// The minted token must carry NEITHER org claim (absent, not empty).
	claims := jwt.MapClaims{}
	if _, _, perr := jwt.NewParser().ParseUnverified(tok, claims); perr != nil {
		t.Fatalf("parse: %v", perr)
	}
	for _, forbidden := range []string{"org", "org_id", "org_roles"} {
		if _, present := claims[forbidden]; present {
			t.Fatalf("%s claim present on minted token: %v", forbidden, claims[forbidden])
		}
	}

	v := newRestoredDelegatedVerifier(t, signer, iss, aud)
	_, dp, err := v.VerifyDelegatedAccess(tok)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if dp.Issuer != iss || dp.DelegatedSubject != "user-123" {
		t.Fatalf("principal=%+v", dp)
	}
}

// TestRestoredDelegatedAccessRolesFromAttributes: attributes.roles UUIDs surface
// on DelegatedPrincipal.Roles + Claims.DelegatedRoles, in order; the native
// top-level Roles claim stays empty.
func TestRestoredDelegatedAccessRolesFromAttributes(t *testing.T) {
	signer, _ := jwtkit.NewRSASigner(2048, "k")
	iss := "https://cozy.example"
	aud := []string{"tensorhub"}
	u1 := "11111111-1111-1111-1111-111111111111"
	u2 := "22222222-2222-2222-2222-222222222222"

	tok, err := MintDelegatedAccessToken(context.Background(), signer, DelegatedAccessParams{
		Issuer:           iss,
		Audiences:        aud,
		DelegatedSubject: "user-123",
		Roles:            []string{u1, u2},
		TTL:              time.Minute,
	})
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	cl, dp, err := newRestoredDelegatedVerifier(t, signer, iss, aud).VerifyDelegatedAccess(tok)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if len(dp.Roles) != 2 || dp.Roles[0] != u1 || dp.Roles[1] != u2 {
		t.Fatalf("principal Roles = %v", dp.Roles)
	}
	if len(cl.DelegatedRoles) != 2 || cl.DelegatedRoles[0] != u1 {
		t.Fatalf("claims DelegatedRoles = %v", cl.DelegatedRoles)
	}
	if len(cl.Roles) != 0 {
		t.Fatalf("native Claims.Roles should be empty on delegated token, got %v", cl.Roles)
	}
}

// TestRestoredDelegatedAccessRolesDropsMalformed: non-UUID/blank/non-string
// entries drop; valid UUIDs survive; the token is not failed.
func TestRestoredDelegatedAccessRolesDropsMalformed(t *testing.T) {
	signer, _ := jwtkit.NewRSASigner(2048, "k")
	iss := "https://cozy.example"
	aud := []string{"tensorhub"}
	good := "33333333-3333-3333-3333-333333333333"
	now := time.Now()

	tok, err := signer.SignWithHeaders(context.Background(), jwt.MapClaims{
		"iss":           iss,
		"aud":           aud,
		"iat":           now.Unix(),
		"exp":           now.Add(time.Minute).Unix(),
		"delegated_sub": "u1",
		"attributes": map[string]any{
			"roles": []any{"not-a-uuid", good, "", 42, "GHIJKLMN-0000-0000-0000-000000000000"},
		},
	}, map[string]any{"typ": DelegatedAccessTokenType})
	if err != nil {
		t.Fatal(err)
	}

	_, dp, err := newRestoredDelegatedVerifier(t, signer, iss, aud).VerifyDelegatedAccess(tok)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if len(dp.Roles) != 1 || dp.Roles[0] != good {
		t.Fatalf("Roles = %v, want [%s]", dp.Roles, good)
	}
}

// TestRestoredDelegatedAccessRolesCapped: more than maxDelegatedRoles UUIDs cap.
func TestRestoredDelegatedAccessRolesCapped(t *testing.T) {
	signer, _ := jwtkit.NewRSASigner(2048, "k")
	iss := "https://cozy.example"
	aud := []string{"tensorhub"}

	roles := make([]string, 0, maxDelegatedRoles+10)
	for i := 0; i < maxDelegatedRoles+10; i++ {
		roles = append(roles, restoredUUIDForIndex(i))
	}
	tok, _ := MintDelegatedAccessToken(context.Background(), signer, DelegatedAccessParams{
		Issuer: iss, Audiences: aud, DelegatedSubject: "u1",
		Roles: roles, TTL: time.Minute,
	})
	_, dp, err := newRestoredDelegatedVerifier(t, signer, iss, aud).VerifyDelegatedAccess(tok)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if len(dp.Roles) != maxDelegatedRoles {
		t.Fatalf("Roles len = %d, want cap %d", len(dp.Roles), maxDelegatedRoles)
	}
}

func restoredUUIDForIndex(i int) string {
	const hex = "0123456789abcdef"
	b := []byte("00000000-0000-4000-8000-000000000000")
	b[len(b)-1] = hex[i&0xf]
	b[len(b)-2] = hex[(i>>4)&0xf]
	return string(b)
}

// TestRestoredVerifierRejectsUnregisteredIssuer: an issuer absent from the
// remote-application store is rejected even when its key would verify.
func TestRestoredVerifierRejectsUnregisteredIssuer(t *testing.T) {
	signer, _ := jwtkit.NewRSASigner(2048, "k")
	v := NewVerifier()
	v.SetRemoteApplicationSource(&memRemoteAppSource{}) // empty store
	tok, _ := MintDelegatedAccessToken(context.Background(), signer, DelegatedAccessParams{
		Issuer: "https://rogue.example", Audiences: []string{"tensorhub"},
		DelegatedSubject: "x", TTL: time.Minute,
	})
	if _, err := v.Verify(tok); err == nil {
		t.Fatal("expected rejection of unregistered issuer")
	}
}

// TestRestoredRequireDelegatedOriginChecksVerifiedIssuer re-creates the
// federation_test.go origin-binding coverage: RequireDelegatedOrigin enforces the
// request Origin against the remote_application registered for the VALIDATED
// issuer. Server-to-server (no Origin) passes; a foreign Origin is forbidden.
func TestRestoredRequireDelegatedOriginChecksVerifiedIssuer(t *testing.T) {
	signer, err := jwtkit.NewRSASigner(2048, "host-kid")
	if err != nil {
		t.Fatal(err)
	}
	jwks := jwksTestServer(t, signer)
	defer jwks.Close()

	iss := "https://auth.doujins.com"
	aud := []string{"openrails"}
	src := &memRemoteAppSource{apps: []authbase.RemoteApplication{{
		Slug:           "doujins",
		Issuer:         iss,
		JWKSURI:        jwks.URL + "/.well-known/jwks.json",
		AllowedOrigins: []string{"https://doujins.com"},
		Enabled:        true,
	}}}
	ver := NewVerifier()
	if err := ver.LoadRemoteApplications(context.Background(), src, aud); err != nil {
		t.Fatalf("LoadRemoteApplications: %v", err)
	}
	// Wire the enricher source too, so Required's fail-closed issuer gate resolves.
	ver.SetRemoteApplicationSource(src)

	tok, err := MintDelegatedAccessToken(context.Background(), signer, DelegatedAccessParams{
		Issuer:           iss,
		Audiences:        aud,
		DelegatedSubject: "external-user-1",
		TTL:              time.Minute,
	})
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	handler := RequireDelegatedOrigin(ver, true)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	for _, tc := range []struct {
		name   string
		origin string
		want   int
	}{
		{name: "matching origin", origin: "https://doujins.com", want: http.StatusOK},
		{name: "no origin server to server", origin: "", want: http.StatusOK},
		{name: "other merchant origin", origin: "https://hentai0.com", want: http.StatusForbidden},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cl, verr := ver.Verify(tok)
			if verr != nil {
				t.Fatalf("verify: %v", verr)
			}
			rec := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodPost, "/memberships/cancel", nil)
			if tc.origin != "" {
				req.Header.Set("Origin", tc.origin)
			}
			// Seed claims as Required would, then run the origin gate.
			req = req.WithContext(setClaims(req.Context(), cl))
			handler.ServeHTTP(rec, req)
			if rec.Code != tc.want {
				t.Fatalf("status = %d, want %d body=%s", rec.Code, tc.want, rec.Body.String())
			}
		})
	}
}

// TestRestoredRemoteApplicationCORSUsesEnabledOriginUnion: preflight is allowed
// only for an enabled remote_application's origin; a disabled app's origin is
// forbidden. (federation_test.go coverage, current credentials-aware handler.)
func TestRestoredRemoteApplicationCORSUsesEnabledOriginUnion(t *testing.T) {
	src := &memRemoteAppSource{apps: []authbase.RemoteApplication{
		{Slug: "doujins", Issuer: "https://auth.doujins.com", AllowedOrigins: []string{"https://doujins.com"}, Enabled: true},
		{Slug: "hentai0", Issuer: "https://auth.hentai0.com", AllowedOrigins: []string{"https://hentai0.com"}, Enabled: false},
	}}
	ver := NewVerifier()
	ver.SetRemoteApplicationSource(src)
	handler := RemoteApplicationCORS(ver)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	allowed := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodOptions, "/memberships/cancel", nil)
	req.Header.Set("Origin", "https://doujins.com")
	req.Header.Set("Access-Control-Request-Method", http.MethodPost)
	handler.ServeHTTP(allowed, req)
	if allowed.Code != http.StatusNoContent {
		t.Fatalf("allowed preflight status = %d body=%s", allowed.Code, allowed.Body.String())
	}
	if got := allowed.Header().Get("Access-Control-Allow-Origin"); got != "https://doujins.com" {
		t.Fatalf("Access-Control-Allow-Origin = %q", got)
	}

	disabled := httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodOptions, "/memberships/cancel", nil)
	req.Header.Set("Origin", "https://hentai0.com")
	handler.ServeHTTP(disabled, req)
	if disabled.Code != http.StatusForbidden {
		t.Fatalf("disabled origin preflight status = %d body=%s", disabled.Code, disabled.Body.String())
	}
}

// jwksTestServer serves a single signer's JWKS, returning its base URL.
func jwksTestServer(t *testing.T, signer *jwtkit.RSASigner) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/jwks.json", func(w http.ResponseWriter, r *http.Request) {
		jwk := jwtkit.PublicToJWK(signer.PublicKey(), signer.KID(), signer.Algorithm())
		jwtkit.ServeJWKS(w, r, jwtkit.JWKS{Keys: []jwtkit.JWK{jwk}})
	})
	return httptest.NewServer(mux)
}
