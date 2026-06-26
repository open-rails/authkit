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
