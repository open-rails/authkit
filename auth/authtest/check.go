// Package authtest checks a host's auth.Authenticator in the host's own CI,
// against the contract the libraries that take it enforce.
package authtest

import (
	"errors"
	"net/http"
	"slices"
	"sort"
	"strings"
	"sync"
	"testing"

	"github.com/open-rails/authkit/auth"
)

// Cases are credentials the host's auth holds when Check runs. Each is a
// function returning a fresh request, since a sender proof is spent once.
type Cases struct {
	// Scope is where Permissions are held. Zero is the Authenticator's
	// RootScope (auth.Root), where root: permissions are held.
	Scope auth.Scope
	// Permissions are the permissions the host gives the library, at least
	// one.
	Permissions []string
	// Staff is a person signed in recently, holding every one of
	// Permissions in Scope.
	Staff func() *http.Request
	// User is another person, signed in, holding none of them in Scope.
	User func() *http.Request
	// Holders are people each holding only the permission they are keyed
	// by. Nil skips the case.
	Holders map[string]func() *http.Request
	// Stale is a person holding every one of Permissions whose sign-in is
	// too old for an action that moves money. Nil skips the case.
	Stale func() *http.Request
	// Application is an application's credential (client credentials, an
	// API key) holding every one of Permissions in Scope. Nil skips the
	// case.
	Application func() *http.Request
	// Refused are credentials Authenticate must refuse, by name: an expired
	// token, a forged one, a signed-out session, a banned or deleted
	// account's.
	Refused map[string]func() *http.Request
	// Bound is a credential bound to Scope (auth.Bound), such as the
	// group's API key or a trusted issuer's token for it. Nil skips the
	// case.
	Bound func() *http.Request
	// Foreign is a credential bound to another scope, such as another
	// group's API key; it holds none of Permissions in Scope. Nil skips the
	// case.
	Foreign func() *http.Request
	// BoundStaff is Staff's sign-in bound to another scope, such as a token
	// exchanged for one group. With Scope the Authenticator's RootScope, it
	// still holds every one of Permissions there: a person keeps their root
	// role (auth.Bound). Nil skips the case.
	BoundStaff func() *http.Request
	// Asserted is a credential minted from an application's assertion
	// (auth.Asserted), such as a backend's token for its customer. Nil skips
	// the case.
	Asserted func() *http.Request
	// Revoke ends the sign-in behind Staff's credential, as signing out
	// does. Check calls it last; Authenticate must then refuse Staff. Nil
	// skips the case.
	Revoke func()
}

const unknownPermission = "authtest:unknown:permission"

// Check fails t when a admits what it must refuse: an anonymous request or
// a Refused credential, a permission to someone who does not hold it, in a
// scope it was not granted in, or for a pattern; a stale sign-in as recent;
// an application as a person or as signed in; a credential bound to one
// scope as bound to another, or holding a permission outside it (but a
// person's in RootScope); any credential but Asserted as asserted, or
// Asserted as not. With auth.Root, it fails when RootScope fails, is not
// whole or changes, when a root: permission is held in a Scope other than
// RootScope, and when BoundStaff loses Staff's root permissions. With
// auth.Headers, it fails when a header Staff's credential is sent in is not
// allowed, or a header a refusal's Challenge carries is not exposed. It
// fails when a refuses Staff, User, a Holder, Application, Bound, Foreign or
// Asserted, so a check cannot pass vacuously, and when an error classifies
// as anything but the contract says (auth.Refuse), so every consumer answers
// it the same.
func Check(t testing.TB, a auth.Authenticator, c Cases) {
	t.Helper()
	if a == nil || len(c.Permissions) == 0 || c.Staff == nil || c.User == nil {
		t.Fatal("authtest: Check needs an Authenticator, Permissions, Staff and User")
		return
	}
	var root auth.Scope
	if r, ok := a.(auth.Root); ok {
		rs, ok := rootScope(t, r)
		switch {
		case !ok:
		case c.Scope == auth.Scope{}:
			c.Scope = rs
		case c.Scope != rs && slices.ContainsFunc(c.Permissions, func(p string) bool { return strings.HasPrefix(p, "root:") }):
			t.Errorf("authtest: Scope %+v is not RootScope %+v, where root: permissions are held", c.Scope, rs)
		}
		root = rs
	}
	if c.Scope.Authority == "" || c.Scope.ID == "" {
		t.Fatal("authtest: Check needs a Scope, or an auth.Root Authenticator's RootScope")
		return
	}
	held := map[string]bool{}
	for _, p := range c.Permissions {
		if p == "" || held[p] {
			t.Fatalf("authtest: Permissions %q has an empty or repeated permission", c.Permissions)
			return
		}
		held[p] = true
	}
	ch := checker{t: t, a: a, scope: c.Scope, atRoot: root != auth.Scope{} && c.Scope == root, permission: c.Permissions[0], challenged: map[string]bool{}}

	ch.refused("an anonymous request", func() *http.Request {
		r := c.Staff()
		r.Header.Del("Authorization")
		r.Header.Del("Cookie")
		r.Header.Del("DPoP")
		return r
	}, http.StatusUnauthorized)
	for _, name := range sortedKeys(c.Refused) {
		ch.refused("the "+name+" credential", c.Refused[name], http.StatusUnauthorized, http.StatusForbidden)
	}

	staff, ok := ch.person("Staff", c.Staff)
	if ok {
		ch.holds("Staff", staff, c.Permissions)
		ch.notGranted("Staff", staff)
		if rs, ok := staff.(auth.RecentSignInChecker); !ok {
			t.Errorf("authtest: Staff's Verified has no CheckRecentSignIn: a person must prove a recent sign-in to move money")
		} else if err := rs.CheckRecentSignIn(t.Context()); err != nil {
			t.Errorf("authtest: CheckRecentSignIn refused Staff, signed in recently: %v", err)
		}
	}
	if user, ok := ch.person("User", c.User); ok {
		if staff != nil && user.Identity().Subject == staff.Identity().Subject {
			t.Errorf("authtest: User and Staff are the same subject %q", staff.Identity().Subject)
		}
		ch.lacks("User", user, c.Permissions)
	}
	for _, own := range sortedKeys(c.Holders) {
		if !held[own] {
			t.Errorf("authtest: Holders names %s, which Permissions does not", own)
			continue
		}
		if v, ok := ch.person("the holder of "+own, c.Holders[own]); ok {
			ch.holds("the holder of "+own, v, []string{own})
			ch.lacks("the holder of "+own, v, slices.DeleteFunc(slices.Clone(c.Permissions), func(p string) bool { return p == own }))
		}
	}
	if c.Stale != nil {
		if v, ok := ch.person("Stale", c.Stale); ok {
			ch.holds("Stale", v, c.Permissions)
			ch.stale(v, c.Stale)
		}
	}
	if c.Application != nil {
		if v, ok := ch.admitted("Application", c.Application); ok {
			if id := v.Identity(); id.SubjectKind != auth.SubjectApplication {
				t.Errorf("authtest: Application's Identity is SubjectKind %q; an application is never a person", id.SubjectKind)
			}
			ch.holds("Application", v, c.Permissions)
			ch.notGranted("Application", v)
			if rs, ok := v.(auth.RecentSignInChecker); ok {
				if err := rs.CheckRecentSignIn(t.Context()); !errors.Is(err, auth.ErrForbidden) {
					t.Errorf("authtest: CheckRecentSignIn answered %v for Application; a credential with no sign-in of its own is auth.ErrForbidden", err)
				}
			}
		}
	}
	if c.Bound != nil {
		if v, ok := ch.admitted("Bound", c.Bound); ok {
			if got, ok := ch.bound("Bound", v); ok && got != c.Scope {
				t.Errorf("authtest: Bound's BoundScope is %+v, not Scope %+v", got, c.Scope)
			}
			ch.notGranted("Bound", v)
		}
	}
	if c.Foreign != nil {
		if v, ok := ch.admitted("Foreign", c.Foreign); ok {
			if got, ok := ch.bound("Foreign", v); ok && (got == auth.Scope{} || got == c.Scope) {
				t.Errorf("authtest: Foreign's BoundScope is %+v; it is bound to a scope other than Scope %+v", got, c.Scope)
			}
			if !ch.rootPerson(v) {
				ch.lacks("Foreign", v, c.Permissions)
			}
		}
	}
	if c.BoundStaff != nil {
		switch v, ok := ch.person("BoundStaff", c.BoundStaff); {
		case !ok:
		case !ch.atRoot:
			t.Errorf("authtest: BoundStaff needs Scope to be the Authenticator's RootScope (auth.Root)")
		default:
			if got, ok := ch.bound("BoundStaff", v); ok && (got == auth.Scope{} || got == c.Scope) {
				t.Errorf("authtest: BoundStaff's BoundScope is %+v; it is bound to a scope other than RootScope %+v", got, c.Scope)
			}
			if staff != nil && v.Identity().Subject != staff.Identity().Subject {
				t.Errorf("authtest: BoundStaff is subject %q, not Staff's %q", v.Identity().Subject, staff.Identity().Subject)
			}
			ch.holds("BoundStaff", v, c.Permissions)
			ch.notGranted("BoundStaff", v)
		}
	}
	if c.Asserted != nil {
		if v, ok := ch.verified("Asserted", c.Asserted); ok {
			if a, ok := v.(auth.Asserted); !ok {
				t.Errorf("authtest: Asserted's Verified has no Asserted")
			} else if !a.Asserted() {
				t.Errorf("authtest: Asserted's Verified answers Asserted() false; it was minted from an application's assertion")
			}
		}
	}
	if catalog, ok := a.(auth.PermissionCatalog); ok {
		for _, p := range c.Permissions {
			if !catalog.KnownPermission(p) {
				t.Errorf("authtest: KnownPermission(%q) is false for a permission Staff holds", p)
			}
		}
		if catalog.KnownPermission(unknownPermission) {
			t.Errorf("authtest: KnownPermission(%q) is true", unknownPermission)
		}
	}

	headers, _ := a.(auth.Headers)
	if headers != nil {
		ch.sentIn(headers, c.Staff)
	}

	errs := make([]error, 8)
	var wg sync.WaitGroup
	for i := range errs {
		wg.Go(func() {
			req := c.Staff
			if i%2 == 1 {
				req = c.User
			}
			_, errs[i] = a.Authenticate(req())
		})
	}
	wg.Wait()
	for _, err := range errs {
		if err != nil {
			t.Errorf("authtest: a concurrent Authenticate failed: %v", err)
			break
		}
	}

	if c.Revoke != nil && staff != nil {
		c.Revoke()
		ch.refused("Staff after Revoke", c.Staff, http.StatusUnauthorized)
	}
	if headers != nil {
		exposed := ch.names("ExposedHeaders", headers.ExposedHeaders())
		for _, name := range sortedKeys(ch.challenged) {
			if !exposed[name] {
				t.Errorf("authtest: a refusal's Challenge carries %s, which ExposedHeaders does not name", name)
			}
		}
	}
}

// rootScope requires RootScope to name one whole scope, the same each time.
func rootScope(t testing.TB, root auth.Root) (auth.Scope, bool) {
	t.Helper()
	first, err := root.RootScope(t.Context())
	if err != nil {
		t.Errorf("authtest: RootScope failed: %v", err)
		return auth.Scope{}, false
	}
	if first.Authority == "" || first.ID == "" {
		t.Errorf("authtest: RootScope is %+v; a scope is whole", first)
		return auth.Scope{}, false
	}
	if again, err := root.RootScope(t.Context()); err != nil || again != first {
		t.Errorf("authtest: RootScope changed from %+v to %+v (%v); it names one scope", first, again, err)
		return auth.Scope{}, false
	}
	return first, true
}

type checker struct {
	t     testing.TB
	a     auth.Authenticator
	scope auth.Scope
	// atRoot is a scope that is the Authenticator's RootScope.
	atRoot bool
	// permission is one every holder of all of them holds in scope.
	permission string
	// challenged are the headers the refusals' Challenges carried.
	challenged map[string]bool
}

// admitted requires Authenticate to admit req, with a whole identity, as a
// credential not minted from an assertion.
func (c checker) admitted(name string, req func() *http.Request) (auth.Verified, bool) {
	c.t.Helper()
	v, ok := c.verified(name, req)
	if ok && asserted(v) {
		c.t.Errorf("authtest: %s's Verified is Asserted; only a credential minted from an application's assertion is", name)
	}
	return v, ok
}

// verified requires Authenticate to admit req, with a whole identity.
func (c checker) verified(name string, req func() *http.Request) (auth.Verified, bool) {
	c.t.Helper()
	v, err := c.a.Authenticate(req())
	switch {
	case err != nil:
		c.t.Errorf("authtest: Authenticate refused %s: %v", name, err)
		return nil, false
	case v == nil:
		c.t.Errorf("authtest: Authenticate admitted %s with no Verified", name)
		return nil, false
	}
	id, bound := v.Identity(), boundScope(v)
	switch {
	case id.Issuer == "" || id.Subject == "" || id.Credential.Kind == "":
		c.t.Errorf("authtest: %s's Identity names no Issuer, Subject or Credential kind: %+v", name, id)
	case id.SubjectKind != auth.SubjectUser && id.SubjectKind != auth.SubjectApplication:
		c.t.Errorf("authtest: %s's Identity is SubjectKind %q, neither a user nor an application", name, id.SubjectKind)
	case id.Invoker.Issuer == "" || id.Invoker.ID == "":
		c.t.Errorf("authtest: %s's Identity names no Invoker; a subject acting itself is its own", name)
	case bound != auth.Scope{} && (bound.Authority == "" || bound.ID == ""):
		c.t.Errorf("authtest: %s's BoundScope is %+v; a scope is whole or zero", name, bound)
	default:
		return v, true
	}
	return nil, false
}

// person requires a person acting itself.
func (c checker) person(name string, req func() *http.Request) (auth.Verified, bool) {
	c.t.Helper()
	v, ok := c.admitted(name, req)
	if !ok {
		return nil, false
	}
	if id := v.Identity(); id.SubjectKind != auth.SubjectUser || !id.SelfInvoked() {
		c.t.Errorf("authtest: %s's Identity is SubjectKind %q, invoked by %+v; a person signed in is a user acting itself", name, id.SubjectKind, id.Invoker)
		return nil, false
	}
	return v, true
}

// refused requires Authenticate to refuse req, as one of statuses.
func (c checker) refused(name string, req func() *http.Request, statuses ...int) {
	c.t.Helper()
	r := req()
	v, err := c.a.Authenticate(r)
	c.challenge(err)
	switch status := auth.Refuse(r, err).Status; {
	case err == nil:
		c.t.Errorf("authtest: Authenticate admitted %s", name)
	case v != nil:
		c.t.Errorf("authtest: Authenticate refused %s but returned a Verified", name)
	case !slices.Contains(statuses, status):
		c.t.Errorf("authtest: Authenticate refused %s with %v, which consumers answer %d, not %v", name, err, status, statuses)
	}
}

func (c checker) can(v auth.Verified, scope auth.Scope, permission string) (bool, error) {
	pc, ok := v.(auth.PermissionChecker)
	if !ok {
		return false, nil
	}
	return pc.Can(c.t.Context(), scope, permission)
}

// holds requires v to hold each of permissions in the scope.
func (c checker) holds(name string, v auth.Verified, permissions []string) {
	c.t.Helper()
	if _, ok := v.(auth.PermissionChecker); !ok {
		c.t.Errorf("authtest: %s's Verified has no Can", name)
		return
	}
	for _, p := range permissions {
		if ok, err := c.can(v, c.scope, p); !ok || err != nil {
			c.t.Errorf("authtest: Can(%+v, %q) refused %s: %v", c.scope, p, name, err)
		}
	}
	if b := boundScope(v); b != (auth.Scope{}) && b != c.scope && !c.rootPerson(v) {
		c.t.Errorf("authtest: %s is bound to %+v but holds permissions in %+v; a bound credential holds nothing outside its scope, but a person's in RootScope", name, b, c.scope)
	}
}

// rootPerson reports a person checked in RootScope, where a person's bound
// credential may hold their root permissions (auth.Bound).
func (c checker) rootPerson(v auth.Verified) bool {
	return c.atRoot && v.Identity().SubjectKind == auth.SubjectUser
}

// lacks requires v to hold none of permissions in the scope.
func (c checker) lacks(name string, v auth.Verified, permissions []string) {
	c.t.Helper()
	for _, p := range permissions {
		if ok, _ := c.can(v, c.scope, p); ok {
			c.t.Errorf("authtest: Can(%+v, %q) granted %s, who does not hold it", c.scope, p, name)
		}
	}
}

// notGranted requires v, holding the permissions in the scope, to hold
// nothing outside it: another scope, another authority's scope of the same
// id, no scope, a pattern, an unknown permission.
func (c checker) notGranted(name string, v auth.Verified) {
	c.t.Helper()
	p := c.permission
	for _, probe := range []struct {
		scope      auth.Scope
		permission string
	}{
		{auth.Scope{Authority: c.scope.Authority, ID: "authtest-other-" + c.scope.ID}, p},
		{auth.Scope{Authority: "https://authtest.invalid", ID: c.scope.ID}, p},
		{auth.Scope{}, p},
		{c.scope, ""},
		{c.scope, "*"},
		{c.scope, p + "*"},
		{c.scope, unknownPermission},
	} {
		if ok, _ := c.can(v, probe.scope, probe.permission); ok {
			c.t.Errorf("authtest: Can(%+v, %q) granted %s: a grant is exactly one permission in exactly one scope", probe.scope, probe.permission, name)
		}
	}
}

// stale requires CheckRecentSignIn to ask v's person to sign in again, as
// a step-up every consumer answers 401.
func (c checker) stale(v auth.Verified, req func() *http.Request) {
	c.t.Helper()
	rs, ok := v.(auth.RecentSignInChecker)
	if !ok {
		c.t.Errorf("authtest: Stale's Verified has no CheckRecentSignIn")
		return
	}
	err := rs.CheckRecentSignIn(c.t.Context())
	c.challenge(err)
	if !errors.Is(err, auth.ErrStepUpRequired) {
		c.t.Errorf("authtest: CheckRecentSignIn answered %v for Stale, not auth.ErrStepUpRequired", err)
		return
	}
	if refusal := auth.Refuse(req(), err); refusal.Status != http.StatusUnauthorized {
		c.t.Errorf("authtest: Stale's step-up %v answers %d, not 401", err, refusal.Status)
	}
}

func boundScope(v auth.Verified) auth.Scope {
	if b, ok := v.(auth.Bound); ok {
		return b.BoundScope()
	}
	return auth.Scope{}
}

func asserted(v auth.Verified) bool {
	a, ok := v.(auth.Asserted)
	return ok && a.Asserted()
}

// bound requires v to report its bound scope.
func (c checker) bound(name string, v auth.Verified) (auth.Scope, bool) {
	c.t.Helper()
	b, ok := v.(auth.Bound)
	if !ok {
		c.t.Errorf("authtest: %s's Verified has no BoundScope", name)
		return auth.Scope{}, false
	}
	return b.BoundScope(), true
}

// challenge records the headers err's Challenge carries.
func (c checker) challenge(err error) {
	var ch *auth.Challenge
	if errors.As(err, &ch) {
		for name := range ch.Header {
			c.challenged[http.CanonicalHeaderKey(name)] = true
		}
	}
}

// sentIn requires AllowedHeaders to name every header of a Staff request
// without which Authenticate refuses it, but those a browser or proxy sets.
func (c checker) sentIn(h auth.Headers, staff func() *http.Request) {
	c.t.Helper()
	allowed := c.names("AllowedHeaders", h.AllowedHeaders())
	for _, name := range sortedKeys(staff().Header) {
		name = http.CanonicalHeaderKey(name)
		if notCORS(name) {
			continue
		}
		r := staff()
		r.Header.Del(name)
		if _, err := c.a.Authenticate(r); err != nil {
			c.challenge(err)
			if !allowed[name] {
				c.t.Errorf("authtest: Staff's credential is sent in %s, which AllowedHeaders does not name", name)
			}
		}
	}
}

// names is a Headers list as a set, requiring each to be a header name.
func (c checker) names(list string, names []string) map[string]bool {
	c.t.Helper()
	out := map[string]bool{}
	for _, name := range names {
		if !isToken(name) {
			c.t.Errorf("authtest: %s names %q, not a header name", list, name)
			continue
		}
		out[http.CanonicalHeaderKey(name)] = true
	}
	return out
}

// notCORS reports a header a browser sets itself (the Fetch standard's
// forbidden request headers) or a proxy sets, never one a client allows.
func notCORS(name string) bool {
	switch name {
	case "Accept-Charset", "Accept-Encoding", "Access-Control-Request-Headers", "Access-Control-Request-Method",
		"Connection", "Content-Length", "Cookie", "Cookie2", "Date", "Dnt", "Expect", "Host", "Keep-Alive",
		"Origin", "Referer", "Set-Cookie", "Te", "Trailer", "Transfer-Encoding", "Upgrade", "Via",
		"Forwarded", "X-Real-Ip":
		return true
	}
	return strings.HasPrefix(name, "Proxy-") || strings.HasPrefix(name, "Sec-") || strings.HasPrefix(name, "X-Forwarded-")
}

// isToken reports an RFC 9110 field name.
func isToken(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		switch {
		case 'a' <= r && r <= 'z', 'A' <= r && r <= 'Z', '0' <= r && r <= '9', strings.ContainsRune("!#$%&'*+-.^_`|~", r):
		default:
			return false
		}
	}
	return true
}

func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
