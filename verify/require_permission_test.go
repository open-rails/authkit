package verify

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	authkit "github.com/open-rails/authkit"
)

type fakeChecker struct {
	allow, called bool
	gotSubject    authkit.Subject
	gotGroupID    string
	gotPerm       authkit.Perm
}

func (f *fakeChecker) CanOnGroup(_ context.Context, subject authkit.Subject, groupID string, perm authkit.Perm) (bool, error) {
	f.called = true
	f.gotSubject, f.gotGroupID, f.gotPerm = subject, groupID, perm
	return f.allow, nil
}

func serveGate(mw func(http.Handler) http.Handler, r *http.Request) (status int, nextCalled bool) {
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		nextCalled = true
		w.WriteHeader(http.StatusOK)
	})
	rec := httptest.NewRecorder()
	mw(next).ServeHTTP(rec, r)
	return rec.Code, nextCalled
}

func reqWithClaims(cl Claims) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "/x", nil)
	return r.WithContext(SetClaims(r.Context(), cl))
}

func rootScope(*http.Request) PermissionScope {
	return PermissionScope{GroupID: "root-id", AuthorityIssuer: "https://auth.test", Persona: "root"}
}

func TestRequirePermission_HumanUser_Allow(t *testing.T) {
	chk := &fakeChecker{allow: true}
	code, next := serveGate(RequirePermission(chk, "root:galleries:update", rootScope), reqWithClaims(Claims{UserID: "u1"}))
	if !next || code != http.StatusOK {
		t.Fatalf("allow: code=%d next=%v", code, next)
	}
	if !chk.called || chk.gotSubject != authkit.UserSubject("u1") ||
		chk.gotGroupID != "root-id" || chk.gotPerm != "root:galleries:update" {
		t.Fatalf("checker got wrong args: %+v", chk)
	}
}

func TestRequirePermission_HumanUser_Deny(t *testing.T) {
	code, next := serveGate(RequirePermission(&fakeChecker{allow: false}, "root:galleries:update", rootScope), reqWithClaims(Claims{UserID: "u1"}))
	if next || code != http.StatusForbidden {
		t.Fatalf("deny: code=%d next=%v", code, next)
	}
}

func TestRequirePermission_TokenCarriedPerm_ShortCircuits(t *testing.T) {
	// API-key / delegated principal: perm is on the token, no UserID; the checker
	// must never be consulted.
	chk := &fakeChecker{allow: false}
	cl := Claims{Permissions: []string{"merchant:checkout:create"}}
	code, next := serveGate(RequirePermission(chk, "merchant:checkout:create", nil), reqWithClaims(cl))
	if !next || code != http.StatusOK {
		t.Fatalf("token perm: code=%d next=%v", code, next)
	}
	if chk.called {
		t.Fatal("checker should not be called when the token carries the perm")
	}
}

func TestRequirePermission_ResourceScoped_PassesInstance(t *testing.T) {
	// resolver extracts the instance (e.g. merchant id) from the path.
	resolve := func(*http.Request) PermissionScope {
		return PermissionScope{GroupID: "merchant-id", AuthorityIssuer: "https://auth.test", Persona: "merchant", Instance: "acme"}
	}
	chk := &fakeChecker{allow: true}
	code, next := serveGate(RequirePermission(chk, "merchant:subscriptions:update", resolve), reqWithClaims(Claims{UserID: "u1"}))
	if !next || code != http.StatusOK {
		t.Fatalf("code=%d next=%v", code, next)
	}
	if chk.gotGroupID != "merchant-id" {
		t.Fatalf("scope not passed through: %+v", chk)
	}
}

func TestRequirePermission_NoClaims_Forbidden(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/x", nil) // no claims in context
	code, next := serveGate(RequirePermission(&fakeChecker{allow: true}, "root:x:y", rootScope), r)
	if next || code != http.StatusForbidden {
		t.Fatalf("no claims should 403: code=%d next=%v", code, next)
	}
}

func TestRequirePermission_NilChecker_Forbidden(t *testing.T) {
	code, next := serveGate(RequirePermission(nil, "root:x:y", rootScope), reqWithClaims(Claims{UserID: "u1"}))
	if next || code != http.StatusForbidden {
		t.Fatalf("nil checker should 403: code=%d next=%v", code, next)
	}
}

// #248: a group-bound machine principal's token-carried authority is valid
// ONLY on the exact permission-group instance it was minted on.
func TestRequirePermission_GroupBoundPrincipal(t *testing.T) {
	bound := Claims{
		TokenType:                      APIKeyPrincipalType,
		Permissions:                    []string{"repo:models:deploy"},
		PermissionGroupID:              "group-alpha",
		PermissionGroupAuthorityIssuer: "https://auth.test",
		PermissionGroupPersona:         "repo",
		PermissionGroupInstance:        "alpha",
	}
	scopeOf := func(inst string) func(*http.Request) PermissionScope {
		return func(*http.Request) PermissionScope {
			return PermissionScope{GroupID: "group-" + inst, AuthorityIssuer: "https://auth.test", Persona: "repo", Instance: inst}
		}
	}

	// Matching instance allows without consulting the checker.
	chk := &fakeChecker{allow: false}
	code, next := serveGate(RequirePermission(chk, "repo:models:deploy", scopeOf("alpha")), reqWithClaims(bound))
	if !next || code != http.StatusOK {
		t.Fatalf("matching instance: code=%d next=%v", code, next)
	}
	if chk.called {
		t.Fatal("checker must not be consulted for a bound token-carried allow")
	}

	// Cross-instance is denied even though the perm string matches.
	code, next = serveGate(RequirePermission(&fakeChecker{allow: true}, "repo:models:deploy", scopeOf("beta")), reqWithClaims(bound))
	if next || code != http.StatusForbidden {
		t.Fatalf("cross-instance must 403: code=%d next=%v", code, next)
	}

	// Fail-closed: a bound principal with no resolvable scope is denied.
	code, next = serveGate(RequirePermission(&fakeChecker{allow: true}, "repo:models:deploy", nil), reqWithClaims(bound))
	if next || code != http.StatusForbidden {
		t.Fatalf("nil resolver must 403 a bound principal: code=%d next=%v", code, next)
	}

	// Wrong persona at the same instance slug is denied.
	orgScope := func(*http.Request) PermissionScope { return PermissionScope{Persona: "org", Instance: "alpha"} }
	code, next = serveGate(RequirePermission(&fakeChecker{}, "repo:models:deploy", orgScope), reqWithClaims(bound))
	if next || code != http.StatusForbidden {
		t.Fatalf("persona mismatch must 403: code=%d next=%v", code, next)
	}
}

func TestAllow_GroupBoundPrincipal(t *testing.T) {
	ctx := context.Background()
	bound := Claims{
		TokenType:                      RemoteApplicationTokenType,
		Permissions:                    []string{"repo:*"},
		PermissionGroupID:              "group-alpha",
		PermissionGroupAuthorityIssuer: "https://auth.test",
		PermissionGroupPersona:         "repo",
		PermissionGroupInstance:        "alpha",
	}
	if ok, err := Allow(ctx, nil, bound, "repo:models:deploy", PermissionScope{GroupID: "group-alpha", AuthorityIssuer: "https://auth.test", Persona: "repo", Instance: "alpha"}); err != nil || !ok {
		t.Fatalf("exact scope must allow: ok=%v err=%v", ok, err)
	}
	if ok, _ := Allow(ctx, nil, bound, "repo:models:deploy", PermissionScope{GroupID: "group-beta", AuthorityIssuer: "https://auth.test", Persona: "repo", Instance: "beta"}); ok {
		t.Fatal("cross-instance must deny")
	}
	if ok, _ := Allow(ctx, nil, bound, "repo:models:deploy", PermissionScope{}); ok {
		t.Fatal("empty scope must deny a bound principal")
	}
	// Unbound claims (delegated model) stay unrestricted by scope.
	unbound := Claims{Permissions: []string{"repo:models:deploy"}}
	if ok, _ := Allow(ctx, nil, unbound, "repo:models:deploy", PermissionScope{GroupID: "group-beta", AuthorityIssuer: "https://auth.test", Persona: "repo", Instance: "beta"}); !ok {
		t.Fatal("unbound token-carried perm must remain scope-free")
	}
}

func TestAllow(t *testing.T) {
	ctx := context.Background()

	// Token-carried perm: allowed without consulting the checker.
	chk := &fakeChecker{allow: false}
	ok, err := Allow(ctx, chk, Claims{Permissions: []string{"root:users:ban"}}, "root:users:ban", PermissionScope{GroupID: "root-id", AuthorityIssuer: "https://auth.test", Persona: "root"})
	if err != nil || !ok {
		t.Fatalf("token-carried: ok=%v err=%v", ok, err)
	}
	if chk.called {
		t.Fatal("checker must not be consulted when the token carries the perm")
	}

	// Glob token grant covers a concrete perm (same matching as the gate).
	ok, _ = Allow(ctx, &fakeChecker{}, Claims{Permissions: []string{"root:*"}}, "root:users:ban", PermissionScope{GroupID: "root-id", AuthorityIssuer: "https://auth.test", Persona: "root"})
	if !ok {
		t.Fatal("glob grant root:* must cover root:users:ban")
	}

	// Human user: resolved via Can in the given scope.
	chk = &fakeChecker{allow: true}
	ok, err = Allow(ctx, chk, Claims{UserID: "u1"}, "root:users:ban", PermissionScope{GroupID: "root-id", AuthorityIssuer: "https://auth.test", Persona: "root"})
	if err != nil || !ok || !chk.called || chk.gotGroupID != "root-id" || chk.gotSubject.Kind != authkit.SubjectKindUser {
		t.Fatalf("human allow: ok=%v err=%v chk=%+v", ok, err, chk)
	}
	if ok, _ := Allow(ctx, &fakeChecker{allow: false}, Claims{UserID: "u1"}, "p", PermissionScope{}); ok {
		t.Fatal("human deny must be false")
	}

	// Fail-closed: nil checker or empty principal.
	if ok, _ := Allow(ctx, nil, Claims{UserID: "u1"}, "p", PermissionScope{}); ok {
		t.Fatal("nil checker must deny")
	}
	if ok, _ := Allow(ctx, &fakeChecker{allow: true}, Claims{}, "p", PermissionScope{}); ok {
		t.Fatal("empty principal (no token perm, no UserID) must deny")
	}
}

// erroringChecker is a checker whose backend is down. It answers ok=true so the
// test proves the error wins over the verdict.
type erroringChecker struct{ called bool }

func (e *erroringChecker) CanOnGroup(context.Context, authkit.Subject, string, authkit.Perm) (bool, error) {
	e.called = true
	return true, errors.New("pg: connection reset by peer")
}

func TestRequirePermission_CheckerError_DeniesAndSkipsNext(t *testing.T) {
	chk := &erroringChecker{}
	code, next := serveGate(RequirePermission(chk, "root:galleries:update", rootScope), reqWithClaims(Claims{UserID: "u1"}))
	if next || code != http.StatusForbidden {
		t.Fatalf("checker error: code=%d next=%v, want 403 and next not called", code, next)
	}
	if !chk.called {
		t.Fatal("checker was never consulted")
	}
	// Allow passes the checker's error through; callers must treat it as deny.
	if _, err := Allow(context.Background(), chk, Claims{UserID: "u1"}, "root:galleries:update", PermissionScope{GroupID: "root-id", AuthorityIssuer: "https://auth.test", Persona: "root"}); err == nil {
		t.Fatal("Allow must surface the checker error")
	}
}

func TestGroupScopeOwnershipIgnoresNamesButRequiresIssuerAndUUID(t *testing.T) {
	base := Claims{TokenType: APIKeyPrincipalType, Permissions: []string{"repo:*"}, PermissionGroupID: "group-a", PermissionGroupAuthorityIssuer: "https://authority.test", PermissionGroupPersona: "repo", PermissionGroupInstance: "old"}
	current := PermissionScope{GroupID: "group-a", AuthorityIssuer: "https://authority.test", Persona: "repo", Instance: "new"}
	if ok, err := Allow(context.Background(), nil, base, "repo:models:deploy", current); err != nil || !ok {
		t.Fatalf("rename changed ownership: %v %v", ok, err)
	}
	for _, mutate := range []func(*PermissionScope){
		func(s *PermissionScope) { s.GroupID = "group-b"; s.Instance = "old" },
		func(s *PermissionScope) { s.AuthorityIssuer = "https://other.test" },
		func(s *PermissionScope) { s.GroupID = "" },
		func(s *PermissionScope) { s.AuthorityIssuer = "" },
	} {
		scope := current
		mutate(&scope)
		if ok, _ := Allow(context.Background(), &fakeChecker{allow: true}, base, "repo:models:deploy", scope); ok {
			t.Fatalf("foreign/missing identity allowed: %+v", scope)
		}
	}
	for _, mutate := range []func(*Claims){
		func(c *Claims) { c.PermissionGroupID = "" },
		func(c *Claims) { c.PermissionGroupAuthorityIssuer = "" },
		func(c *Claims) { c.PermissionGroupPersona = "" },
		func(c *Claims) { c.PermissionGroupID = "group-b"; c.UserID = "human" },
	} {
		claims := base
		mutate(&claims)
		if ok, _ := Allow(context.Background(), &fakeChecker{allow: true}, claims, "repo:models:deploy", current); ok {
			t.Fatalf("malformed binding/human fallback allowed: %+v", claims)
		}
	}
}

func TestRequirePermissionPassesCapturedUUIDToHandler(t *testing.T) {
	scope := PermissionScope{GroupID: "captured-group", AuthorityIssuer: "https://auth.test", Persona: "repo", Instance: "current"}
	called := false
	handler := RequirePermission(&fakeChecker{allow: true}, "repo:models:deploy", func(*http.Request) PermissionScope { return scope })(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got, ok := PermissionScopeFromContext(r.Context())
		if !ok || got != scope {
			t.Fatalf("handler scope=%+v %v", got, ok)
		}
		called = true
	}))
	handler.ServeHTTP(httptest.NewRecorder(), reqWithClaims(Claims{UserID: "user"}))
	if !called {
		t.Fatal("authorized handler not called")
	}
}

func TestHumanTokenPermissionsDoNotReplaceLiveMembership(t *testing.T) {
	checker := &fakeChecker{allow: false}
	ok, err := Allow(context.Background(), checker, Claims{UserID: "user", Permissions: []string{"root:*"}}, "root:users:ban", rootScope(nil))
	if err != nil || ok || !checker.called {
		t.Fatalf("user permissions bypassed live membership: %v %v called=%v", ok, err, checker.called)
	}
}
