package authtest_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/open-rails/authkit/auth"
	"github.com/open-rails/authkit/auth/authtest"
)

const issuer = "https://host.example"

var (
	scope = auth.Scope{Authority: issuer, ID: "root"}
	other = auth.Scope{Authority: issuer, ID: "merchant-2"}
)

var perms = []string{"root:billing:read", "root:billing:refund"}

// host is an in-memory Authenticator; its flags break it the ways Check
// must catch.
type host struct {
	mu    sync.Mutex
	creds map[string]*cred

	anonymousAdmitted bool // no credential reads as the customer
	forgedAdmitted    bool // an unknown token reads as the customer
	unclassified      bool // refusals are bare errors
	verifiedWithError bool // a refusal also returns a Verified
	scopeIgnored      bool // Can ignores the scope
	authorityIgnored  bool // Can ignores the scope's authority
	patterns          bool // Can reads "*" as a wildcard
	everyoneHolds     bool // Can grants every person everything
	noCan             bool // Verified has no Can
	noRecentSignIn    bool // Verified has no CheckRecentSignIn
	staleAccepted     bool // every sign-in is recent
	staleForbidden    bool // a stale sign-in is ErrForbidden, not a step-up
	appAsUser         bool // the application reads as a person
	appSignedIn       bool // the application passes CheckRecentSignIn
	noInvoker         bool // Identity names no invoker
	notLive           bool // a revoked sign-in is still admitted
	knowsEverything   bool // KnownPermission is always true
	noBound           bool // Verified has no BoundScope
	boundElsewhere    bool // a credential bound to scope reports other
	foreignHere       bool // a credential bound to other reports scope
	halfBound         bool // a bound scope names no authority
	sessionsBound     bool // sessions report other as their bound scope
	dpopNotAllowed    bool // AllowedHeaders omits DPoP
	nonceNotExposed   bool // ExposedHeaders omits DPoP-Nonce
	badHeaderName     bool // AllowedHeaders names a list, not a header
	boundStaffStrict  bool // a person's bound token holds nothing at root
	appsHoldRoot      bool // an application's bound token holds at root too
	rootFails         bool // RootScope cannot be resolved
	rootHalf          bool // RootScope names no authority
	rootUnstable      bool // RootScope names another scope each time
	rootElsewhere     bool // RootScope is not where root: permissions are held
	noAsserted        bool // Verified has no Asserted
	assertionIgnored  bool // the assertion's credential is not asserted
	everyoneAsserted  bool // every credential is asserted
	rootCalls         int
}

type cred struct {
	id       auth.Identity
	grants   []string
	in       auth.Scope // where grants are held: scope when zero
	bound    auth.Scope
	signedIn time.Time
	revoked  bool
	proof    bool // DPoP-bound: refused without a proof
	asserted bool
}

func newHost() *host {
	user := func(id string, signedIn time.Time, grants ...string) *cred {
		return &cred{id: auth.Identity{
			Issuer: issuer, Subject: id, SubjectKind: auth.SubjectUser,
			Invoker:    auth.Invoker{Issuer: issuer, ID: id},
			Credential: auth.Credential{Kind: auth.CredentialSession, ID: "s-" + id},
		}, grants: grants, signedIn: signedIn}
	}
	app := func(id, key string, bound auth.Scope) *cred {
		return &cred{id: auth.Identity{
			Issuer: issuer, Subject: id, SubjectKind: auth.SubjectApplication,
			Invoker:    auth.Invoker{Issuer: issuer, ID: id},
			Credential: auth.Credential{Kind: auth.CredentialAPIKey, ID: key},
		}, grants: perms, in: bound, bound: bound}
	}
	now := time.Now()
	staff := user("u-staff", now, perms...)
	staff.proof = true
	// Staff's sign-in exchanged for a token bound to other.
	exchanged := user("u-staff", now, perms...)
	exchanged.id.Credential = auth.Credential{Kind: auth.CredentialAccessToken, ID: "x-u-staff"}
	exchanged.bound = other
	return &host{creds: map[string]*cred{
		"staff":     staff,
		"exchanged": exchanged,
		"customer":  user("u-customer", now),
		"reader":    user("u-reader", now, "root:billing:read"),
		"stale":     user("u-stale", now.Add(-time.Hour), perms...),
		"key":       app("app-1", "key-1", scope),
		"other":     app("app-2", "key-2", other),
		// a trusted issuer's customer token, bound to its group
		"member": {id: auth.Identity{
			Issuer: "https://issuer.example", Subject: "c-1", SubjectKind: auth.SubjectUser,
			Invoker:    auth.Invoker{Issuer: "https://issuer.example", ID: "c-1"},
			Credential: auth.Credential{Kind: auth.CredentialAccessToken, ID: "jti-1"},
		}, bound: scope, signedIn: now},
		// a customer token minted from its backend's assertion
		"asserted": {id: auth.Identity{
			Issuer: "https://backend.example", Subject: "c-2", SubjectKind: auth.SubjectUser,
			Invoker:    auth.Invoker{Issuer: "https://backend.example", ID: "c-2"},
			Credential: auth.Credential{Kind: auth.CredentialAccessToken, ID: "jti-2"},
		}, bound: scope, asserted: true},
	}}
}

func (h *host) refusal(err error) error {
	if h.unclassified {
		return errors.New("no such session")
	}
	return err
}

func (h *host) Authenticate(r *http.Request) (auth.Verified, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	token := ""
	if fields := strings.Fields(r.Header.Get("Authorization")); len(fields) == 2 {
		token = fields[1]
	}
	c, ok := h.creds[token]
	switch {
	case token == "" && h.anonymousAdmitted, !ok && token != "" && h.forgedAdmitted:
		c = h.creds["customer"]
	case !ok:
		if h.verifiedWithError {
			return h.verified(h.creds["customer"]), h.refusal(auth.ErrUnauthenticated)
		}
		return nil, h.refusal(auth.ErrUnauthenticated)
	case c.revoked && !h.notLive:
		return nil, h.refusal(errors.Join(auth.ErrUnauthenticated, auth.ErrRevoked))
	// the proof's URL is https, behind a proxy terminating TLS
	case c.proof && (r.Header.Get("DPoP") == "" || r.Header.Get("X-Forwarded-Proto") != "https"):
		return nil, &auth.Challenge{
			Err:    errors.Join(auth.ErrUnauthenticated, auth.ErrSenderProofRequired),
			Header: http.Header{"WWW-Authenticate": {`DPoP error="use_dpop_nonce"`}, "DPoP-Nonce": {"n-1"}},
		}
	}
	return h.verified(c), nil
}

func (h *host) verified(c *cred) auth.Verified {
	id := c.id
	if h.appAsUser && id.SubjectKind == auth.SubjectApplication {
		id.SubjectKind = auth.SubjectUser
	}
	if h.noInvoker {
		id.Invoker = auth.Invoker{}
	}
	base := verified{h: h, c: c, id: id}
	switch {
	case h.noBound:
		return unbound{base}
	case h.noCan:
		return identityOnly{base}
	case h.noRecentSignIn:
		return canOnly{base}
	case h.noAsserted:
		return unasserted{base}
	}
	return base
}

func (h *host) RootScope(context.Context) (auth.Scope, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.rootCalls++
	switch {
	case h.rootFails:
		return auth.Scope{}, auth.ErrUnavailable
	case h.rootHalf:
		return auth.Scope{ID: scope.ID}, nil
	case h.rootUnstable && h.rootCalls > 1, h.rootElsewhere:
		return other, nil
	}
	return scope, nil
}

func (h *host) KnownPermission(p string) bool { return h.knowsEverything || slices.Contains(perms, p) }

func (h *host) AllowedHeaders() []string {
	switch {
	case h.dpopNotAllowed:
		return []string{"Authorization"}
	case h.badHeaderName:
		return []string{"Authorization, DPoP"}
	}
	return []string{"Authorization", "DPoP"}
}

func (h *host) ExposedHeaders() []string {
	if h.nonceNotExposed {
		return []string{"WWW-Authenticate"}
	}
	return []string{"WWW-Authenticate", "DPoP-Nonce"}
}

type verified struct {
	h  *host
	c  *cred
	id auth.Identity
}

func (v verified) Identity() auth.Identity { return v.id }

func (v verified) Can(_ context.Context, s auth.Scope, p string) (bool, error) {
	h := v.h
	switch {
	case h.everyoneHolds && v.c.id.SubjectKind == auth.SubjectUser:
		return true, nil
	case h.patterns && strings.HasSuffix(p, "*"):
		return slices.ContainsFunc(v.c.grants, func(g string) bool { return strings.HasPrefix(g, strings.TrimSuffix(p, "*")) }), nil
	}
	in := v.c.in
	if in == (auth.Scope{}) {
		in = scope
	}
	switch b := v.c.bound; {
	case h.appsHoldRoot && b != auth.Scope{} && v.c.id.SubjectKind == auth.SubjectApplication && s == scope:
		return true, nil
	case h.boundStaffStrict && b != auth.Scope{} && v.c.id.SubjectKind == auth.SubjectUser && s != b:
		return false, nil
	}
	if h.scopeIgnored || h.authorityIgnored && s.ID == in.ID || s == in {
		return slices.Contains(v.c.grants, p), nil
	}
	return false, nil
}

func (v verified) BoundScope() auth.Scope {
	h, b := v.h, v.c.bound
	switch {
	case h.sessionsBound && v.c.id.Credential.Kind == auth.CredentialSession:
		return other
	case h.boundElsewhere && b == scope:
		return other
	case h.foreignHere && b == other:
		return scope
	case h.halfBound && b != auth.Scope{}:
		return auth.Scope{ID: b.ID}
	}
	return b
}

func (v verified) CheckRecentSignIn(context.Context) error {
	h := v.h
	switch {
	case v.c.id.SubjectKind == auth.SubjectApplication && !h.appSignedIn:
		return auth.ErrForbidden
	case h.staleAccepted, time.Since(v.c.signedIn) < 15*time.Minute:
		return nil
	case h.staleForbidden:
		return auth.ErrForbidden
	}
	return &auth.Challenge{Err: auth.ErrStepUpRequired, MaxAge: 15 * time.Minute}
}

func (v verified) Asserted() bool {
	return v.h.everyoneAsserted || v.c.asserted && !v.h.assertionIgnored
}

// unbound is a Verified without BoundScope.
type unbound struct{ v verified }

func (u unbound) Identity() auth.Identity { return u.v.Identity() }
func (u unbound) Can(ctx context.Context, s auth.Scope, p string) (bool, error) {
	return u.v.Can(ctx, s, p)
}
func (u unbound) CheckRecentSignIn(ctx context.Context) error { return u.v.CheckRecentSignIn(ctx) }

// unasserted is a Verified without Asserted.
type unasserted struct{ v verified }

func (u unasserted) Identity() auth.Identity { return u.v.Identity() }
func (u unasserted) Can(ctx context.Context, s auth.Scope, p string) (bool, error) {
	return u.v.Can(ctx, s, p)
}
func (u unasserted) CheckRecentSignIn(ctx context.Context) error { return u.v.CheckRecentSignIn(ctx) }
func (u unasserted) BoundScope() auth.Scope                      { return u.v.BoundScope() }

type canOnly struct{ v verified }

func (c canOnly) Identity() auth.Identity { return c.v.Identity() }
func (c canOnly) Can(ctx context.Context, s auth.Scope, p string) (bool, error) {
	return c.v.Can(ctx, s, p)
}

type identityOnly struct{ v verified }

func (i identityOnly) Identity() auth.Identity { return i.v.Identity() }

func (h *host) cases() authtest.Cases {
	req := func(token string) func() *http.Request {
		return func() *http.Request {
			r := httptest.NewRequest(http.MethodGet, "https://billing.example/v1/admin/payments", nil)
			r.Header.Set("Authorization", "Bearer "+token)
			return r
		}
	}
	return authtest.Cases{
		Scope:       scope,
		Permissions: perms,
		Staff: func() *http.Request {
			r := req("staff")()
			r.Header.Set("Authorization", "DPoP staff")
			r.Header.Set("DPoP", "proof")
			r.Header.Set("X-Forwarded-Proto", "https")
			return r
		},
		User:        req("customer"),
		Holders:     map[string]func() *http.Request{"root:billing:read": req("reader")},
		Stale:       req("stale"),
		Application: req("key"),
		Bound:       req("member"),
		Foreign:     req("other"),
		BoundStaff:  req("exchanged"),
		Asserted:    req("asserted"),
		Refused:     map[string]func() *http.Request{"forged": req("forged")},
		Revoke: func() {
			h.mu.Lock()
			h.creds["staff"].revoked = true
			h.mu.Unlock()
		},
	}
}

// recorder captures Check's failures instead of failing the test.
type recorder struct {
	testing.TB
	failures []string
}

func (r *recorder) Errorf(format string, args ...any) { r.failures = append(r.failures, format) }
func (r *recorder) Fatal(args ...any)                 { r.failures = append(r.failures, "fatal") }
func (r *recorder) Fatalf(format string, args ...any) { r.failures = append(r.failures, format) }
func (r *recorder) Helper()                           {}

func TestCheckPassesAConformingAuthenticator(t *testing.T) {
	h := newHost()
	authtest.Check(t, h, h.cases())
}

// TestCheckTakesRootScope: without a Scope, Permissions are held in the
// Authenticator's RootScope.
func TestCheckTakesRootScope(t *testing.T) {
	h := newHost()
	c := h.cases()
	c.Scope = auth.Scope{}
	authtest.Check(t, h, c)
}

// bare hides the host's optional capabilities (Root, Headers,
// PermissionCatalog).
type bare struct{ h *host }

func (b bare) Authenticate(r *http.Request) (auth.Verified, error) { return b.h.Authenticate(r) }

func TestCheckPassesWithoutHeaders(t *testing.T) {
	h := newHost()
	h.nonceNotExposed, h.dpopNotAllowed = true, true
	c := h.cases()
	c.BoundStaff = nil // checked in RootScope only
	authtest.Check(t, bare{h}, c)
}

func TestCheckCatchesABrokenAuthenticator(t *testing.T) {
	for name, c := range map[string]struct {
		breakIt func(*host)
		want    string // in the failure Check must report
	}{
		"admits anonymous":          {func(h *host) { h.anonymousAdmitted = true }, "admitted %s"},
		"admits a forged token":     {func(h *host) { h.forgedAdmitted = true }, "admitted %s"},
		"unclassified refusals":     {func(h *host) { h.unclassified = true }, "which consumers answer"},
		"a Verified with an error":  {func(h *host) { h.verifiedWithError = true }, "returned a Verified"},
		"ignores the scope":         {func(h *host) { h.scopeIgnored = true }, "exactly one scope"},
		"ignores the authority":     {func(h *host) { h.authorityIgnored = true }, "exactly one scope"},
		"grants patterns":           {func(h *host) { h.patterns = true }, "exactly one permission"},
		"every person holds all":    {func(h *host) { h.everyoneHolds = true }, "who does not hold it"},
		"no Can":                    {func(h *host) { h.noCan = true }, "has no Can"},
		"no recent sign-in check":   {func(h *host) { h.noRecentSignIn = true }, "has no CheckRecentSignIn"},
		"a stale sign-in is recent": {func(h *host) { h.staleAccepted = true }, "not auth.ErrStepUpRequired"},
		"a stale sign-in refused":   {func(h *host) { h.staleForbidden = true }, "not auth.ErrStepUpRequired"},
		"an application as person":  {func(h *host) { h.appAsUser = true }, "never a person"},
		"an application signed in":  {func(h *host) { h.appSignedIn = true }, "no sign-in of its own"},
		"no invoker":                {func(h *host) { h.noInvoker = true }, "names no Invoker"},
		"not live":                  {func(h *host) { h.notLive = true }, "admitted %s"},
		"knows every permission":    {func(h *host) { h.knowsEverything = true }, "KnownPermission(%q) is true"},
		"no BoundScope":             {func(h *host) { h.noBound = true }, "has no BoundScope"},
		"bound elsewhere":           {func(h *host) { h.boundElsewhere = true }, "not Scope"},
		"a foreign key bound here":  {func(h *host) { h.foreignHere = true }, "a scope other than Scope"},
		"half a bound scope":        {func(h *host) { h.halfBound = true }, "whole or zero"},
		"sessions bound elsewhere":  {func(h *host) { h.sessionsBound = true }, "nothing outside its scope"},
		"DPoP not allowed":          {func(h *host) { h.dpopNotAllowed = true }, "AllowedHeaders does not name"},
		"nonce not exposed":         {func(h *host) { h.nonceNotExposed = true }, "ExposedHeaders does not name"},
		"a list as a header name":   {func(h *host) { h.badHeaderName = true }, "not a header name"},
		"RootScope fails":           {func(h *host) { h.rootFails = true }, "RootScope failed"},
		"half a root scope":         {func(h *host) { h.rootHalf = true }, "a scope is whole"},
		"an unstable root scope":    {func(h *host) { h.rootUnstable = true }, "it names one scope"},
		"root: held outside root":   {func(h *host) { h.rootElsewhere = true }, "is not RootScope"},
		"a bound person loses root": {func(h *host) { h.boundStaffStrict = true }, "refused %s"},
		"a bound app holds root":    {func(h *host) { h.appsHoldRoot = true }, "who does not hold it"},
		"no Asserted":               {func(h *host) { h.noAsserted = true }, "has no Asserted"},
		"an assertion not asserted": {func(h *host) { h.assertionIgnored = true }, "answers Asserted() false"},
		"everyone asserted":         {func(h *host) { h.everyoneAsserted = true }, "only a credential minted"},
	} {
		t.Run(name, func(t *testing.T) {
			h := newHost()
			c.breakIt(h)
			r := &recorder{TB: t}
			var a auth.Authenticator = h
			if name == "sessions bound elsewhere" { // in RootScope a person's bound sign-in may hold its root role
				a = bare{h}
			}
			authtest.Check(r, a, h.cases())
			if !slices.ContainsFunc(r.failures, func(f string) bool { return strings.Contains(f, c.want) }) {
				t.Fatalf("Check reported %q, not %q", r.failures, c.want)
			}
		})
	}
}

// TestCheckBoundStaffNeedsRootScope: BoundStaff is checked in RootScope
// only; without auth.Root, Check says so.
func TestCheckBoundStaffNeedsRootScope(t *testing.T) {
	h := newHost()
	r := &recorder{TB: t}
	authtest.Check(r, bare{h}, h.cases())
	if !slices.ContainsFunc(r.failures, func(f string) bool { return strings.Contains(f, "BoundStaff needs Scope") }) {
		t.Fatalf("Check reported %q", r.failures)
	}
}

func TestCheckRefusesIncompleteCases(t *testing.T) {
	h := newHost()
	for name, edit := range map[string]func(*authtest.Cases){
		"no scope":              func(c *authtest.Cases) { c.Scope = auth.Scope{} },
		"half a scope":          func(c *authtest.Cases) { c.Scope.Authority = "" },
		"no permissions":        func(c *authtest.Cases) { c.Permissions = nil },
		"a repeated permission": func(c *authtest.Cases) { c.Permissions = []string{"root:billing:read", "root:billing:read"} },
		"no staff":              func(c *authtest.Cases) { c.Staff = nil },
		"no user":               func(c *authtest.Cases) { c.User = nil },
	} {
		t.Run(name, func(t *testing.T) {
			c := h.cases()
			edit(&c)
			r := &recorder{TB: t}
			authtest.Check(r, bare{h}, c)
			if len(r.failures) != 1 {
				t.Fatalf("drew %v", r.failures)
			}
		})
	}
}
