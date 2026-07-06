package verify

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

type fakeChecker struct {
	allow                                             bool
	called                                            bool
	gotSubject, gotKind, gotPersona, gotInst, gotPerm string
}

func (f *fakeChecker) Can(_ context.Context, subjectID, subjectKind, persona, instanceSlug, perm string) (bool, error) {
	f.called = true
	f.gotSubject, f.gotKind, f.gotPersona, f.gotInst, f.gotPerm = subjectID, subjectKind, persona, instanceSlug, perm
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

func rootScope(*http.Request) PermissionScope { return PermissionScope{Persona: "root"} }

func TestRequirePermission_HumanUser_Allow(t *testing.T) {
	chk := &fakeChecker{allow: true}
	code, next := serveGate(RequirePermission(chk, "root:galleries:update", rootScope), reqWithClaims(Claims{UserID: "u1"}))
	if !next || code != http.StatusOK {
		t.Fatalf("allow: code=%d next=%v", code, next)
	}
	if !chk.called || chk.gotSubject != "u1" || chk.gotKind != subjectKindUser ||
		chk.gotPersona != "root" || chk.gotPerm != "root:galleries:update" {
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
	resolve := func(*http.Request) PermissionScope { return PermissionScope{Persona: "merchant", Instance: "acme"} }
	chk := &fakeChecker{allow: true}
	code, next := serveGate(RequirePermission(chk, "merchant:subscriptions:update", resolve), reqWithClaims(Claims{UserID: "u1"}))
	if !next || code != http.StatusOK {
		t.Fatalf("code=%d next=%v", code, next)
	}
	if chk.gotPersona != "merchant" || chk.gotInst != "acme" {
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
		TokenType:               APIKeyPrincipalType,
		Permissions:             []string{"repo:models:deploy"},
		PermissionGroupPersona:  "repo",
		PermissionGroupInstance: "alpha",
	}
	scopeOf := func(inst string) func(*http.Request) PermissionScope {
		return func(*http.Request) PermissionScope { return PermissionScope{Persona: "repo", Instance: inst} }
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
		TokenType:               RemoteApplicationTokenType,
		Permissions:             []string{"repo:*"},
		PermissionGroupPersona:  "repo",
		PermissionGroupInstance: "alpha",
	}
	if ok, err := Allow(ctx, nil, bound, "repo:models:deploy", PermissionScope{Persona: "repo", Instance: "alpha"}); err != nil || !ok {
		t.Fatalf("exact scope must allow: ok=%v err=%v", ok, err)
	}
	if ok, _ := Allow(ctx, nil, bound, "repo:models:deploy", PermissionScope{Persona: "repo", Instance: "beta"}); ok {
		t.Fatal("cross-instance must deny")
	}
	if ok, _ := Allow(ctx, nil, bound, "repo:models:deploy", PermissionScope{}); ok {
		t.Fatal("empty scope must deny a bound principal")
	}
	// Unbound claims (delegated model) stay unrestricted by scope.
	unbound := Claims{Permissions: []string{"repo:models:deploy"}}
	if ok, _ := Allow(ctx, nil, unbound, "repo:models:deploy", PermissionScope{Persona: "repo", Instance: "beta"}); !ok {
		t.Fatal("unbound token-carried perm must remain scope-free")
	}
}

func TestAllow(t *testing.T) {
	ctx := context.Background()

	// Token-carried perm: allowed without consulting the checker.
	chk := &fakeChecker{allow: false}
	ok, err := Allow(ctx, chk, Claims{Permissions: []string{"root:users:ban"}}, "root:users:ban", PermissionScope{Persona: "root"})
	if err != nil || !ok {
		t.Fatalf("token-carried: ok=%v err=%v", ok, err)
	}
	if chk.called {
		t.Fatal("checker must not be consulted when the token carries the perm")
	}

	// Glob token grant covers a concrete perm (same matching as the gate).
	ok, _ = Allow(ctx, &fakeChecker{}, Claims{Permissions: []string{"root:*"}}, "root:users:ban", PermissionScope{Persona: "root"})
	if !ok {
		t.Fatal("glob grant root:* must cover root:users:ban")
	}

	// Human user: resolved via Can in the given scope.
	chk = &fakeChecker{allow: true}
	ok, err = Allow(ctx, chk, Claims{UserID: "u1"}, "root:users:ban", PermissionScope{Persona: "root"})
	if err != nil || !ok || !chk.called || chk.gotPersona != "root" || chk.gotKind != subjectKindUser {
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
