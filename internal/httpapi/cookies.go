package httpapi

// Cookie registry (ak#395). Every cookie name/path/domain AuthKit issues is
// listed here, one variant per deployment scheme. Setting, rotating or
// clearing a cookie expires the other variants, and the refresh reader
// tolerates the other scheme's, so a deployment that switches scheme never
// strands a browser's session. A changed cookie shape must be added here as
// a new variant, never edited in place, and no variant may be removed.

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"strings"

	"github.com/open-rails/authkit/iam"
)

type cookieKind string

const (
	CookieRefresh      cookieKind = "refresh"
	CookieActiveTenant cookieKind = "active_tenant"
	CookieOIDCState    cookieKind = "oidc_state"
	CookieDevice       cookieKind = "device"
	// CookieDevicePartitioned is the device cookie a third-party iframe keeps:
	// SameSite=None, Partitioned (CHIPS), so it is per top-level site.
	CookieDevicePartitioned cookieKind = "device_partitioned"
	OIDCStatePrefix                    = "authkit_oauth_state_"
)

// CookieVariant is one cookie shape AuthKit issues. An OIDC state name is a
// prefix completed by stateCookieName.
type CookieVariant struct {
	Kind   cookieKind
	Name   string
	Path   string
	Domain string // AuthKit never sets Domain: every variant is host-only
	Secure bool   // issued on HTTPS deployments (always true for __Host-)
	// Current marks the variant AuthKit issues now, per Secure mode.
	Current bool
}

// CookieRegistry is append-only.
var CookieRegistry = []CookieVariant{
	{Kind: CookieRefresh, Name: "authkit_rt", Path: "/"},
	{Kind: CookieRefresh, Name: "__Host-authkit_rt", Path: "/", Secure: true},
	{Kind: CookieOIDCState, Name: OIDCStatePrefix, Path: "/", Current: true},
	{Kind: CookieOIDCState, Name: "__Host-" + OIDCStatePrefix, Path: "/", Secure: true, Current: true},
	{Kind: CookieDevice, Name: "authkit_device", Path: "/", Current: true},
	{Kind: CookieDevice, Name: "__Host-authkit_device", Path: "/", Secure: true, Current: true},
	{Kind: CookieDevicePartitioned, Name: "__Host-authkit_device_p", Path: "/", Secure: true, Current: true},
	{Kind: CookieRefresh, Name: "authkit_rt_{issuer}", Path: "/"},
	{Kind: CookieRefresh, Name: "__Host-authkit_rt_{issuer}", Path: "/", Secure: true},
	{Kind: CookieRefresh, Name: "authkit_rt_{issuer_tenant}", Path: "/", Current: true},
	{Kind: CookieRefresh, Name: "__Host-authkit_rt_{issuer_tenant}", Path: "/", Secure: true, Current: true},
	{Kind: CookieActiveTenant, Name: "authkit_tenant_{issuer}", Path: "/", Current: true},
	{Kind: CookieActiveTenant, Name: "__Host-authkit_tenant_{issuer}", Path: "/", Secure: true, Current: true},
}

// IssuerRefreshCookieName resolves the current default refresh-cookie shape.
// Ports do not scope browser cookies; the complete issuer identifies its slot.
func IssuerRefreshCookieName(issuer string, secure bool) string {
	sum := sha256.Sum256([]byte(issuer))
	name := "authkit_rt_" + hex.EncodeToString(sum[:16])
	if secure {
		name = "__Host-" + name
	}
	return name
}

// TenantRefreshCookieName isolates browser sessions for one issuer and tenant.
// An optional configured base changes the label, never the isolation boundary.
func TenantRefreshCookieName(issuer string, tenant iam.TenantID, base string, secure bool) string {
	if base == "" {
		base = "authkit_rt"
	}
	sum := sha256.Sum256([]byte(issuer + "\x00" + tenant.String()))
	name := base + "_" + hex.EncodeToString(sum[:16])
	if secure {
		name = "__Host-" + name
	}
	return name
}

// ActiveTenantCookieName is a routing hint for the unbound central portal.
// It is not a credential and is ignored by a fixed tenant mount.
func ActiveTenantCookieName(issuer string, secure bool) string {
	sum := sha256.Sum256([]byte(issuer))
	name := "authkit_tenant_" + hex.EncodeToString(sum[:16])
	if secure {
		name = "__Host-" + name
	}
	return name
}

func CurrentCookie(kind cookieKind, secure bool) CookieVariant {
	for _, v := range CookieRegistry {
		if v.Kind == kind && v.Current && v.Secure == secure {
			return v
		}
	}
	panic("httpapi: cookie registry has no current " + string(kind) + " variant")
}

// expired is the Set-Cookie that deletes the variant: name, path and domain
// identify a cookie. Secure follows the deployment (a browser only lets a
// secure origin overwrite a Secure cookie) and is required for __Host-.
func (v CookieVariant) expired(name string, secure bool) *http.Cookie {
	return &http.Cookie{Name: name, Value: "", Path: v.Path, Domain: v.Domain, MaxAge: -1,
		HttpOnly: true, Secure: secure || strings.HasPrefix(name, "__Host-"), SameSite: http.SameSiteLaxMode}
}

// expireCookieVariants deletes every variant of kind other than keep (nil:
// all of them); with presentOnly, only names the request carries. name
// completes a variant's name (the per-flow OIDC state suffix).
func expireCookieVariants(w http.ResponseWriter, r *http.Request, kind cookieKind, keep *CookieVariant, secure bool, name func(CookieVariant) string, presentOnly bool) {
	done := map[string]bool{}
	for _, v := range CookieRegistry {
		n := name(v)
		if v.Kind != kind || done[n+" "+v.Path] || (keep != nil && keep.Name == v.Name && keep.Path == v.Path) {
			continue
		}
		if presentOnly {
			if _, err := r.Cookie(n); err != nil {
				continue
			}
		}
		done[n+" "+v.Path] = true
		http.SetCookie(w, v.expired(n, secure))
	}
}

// refreshCookieCandidate reads the refresh token among the registry variants.
// The current variant wins; otherwise a lone value of the other scheme's
// variant is accepted. More than one value of a name is a same-path duplicate
// (cookie tossing) and is refused outright.
func refreshCookieCandidate(r *http.Request, variants ...CookieVariant) (string, bool) {
	values := map[string][]string{}
	for _, c := range r.Cookies() {
		values[c.Name] = append(values[c.Name], strings.TrimSpace(c.Value))
	}
	for _, v := range variants {
		if len(values[v.Name]) > 1 {
			return "", false
		}
	}
	for _, v := range variants {
		if vals := values[v.Name]; len(vals) == 1 {
			return vals[0], vals[0] != ""
		}
	}
	return "", false
}

// isRefreshCookieName reports whether name is a registered refresh cookie.
func isRefreshCookieName(name string) bool {
	for _, v := range CookieRegistry {
		if v.Kind == CookieRefresh && !v.Current && v.Name == name {
			return true
		}
	}
	return false
}

// Identity describes a cookie variant for diagnostics.
func (v CookieVariant) Identity() string {
	return fmt.Sprintf("%s name=%s path=%s domain=%q secure=%v", v.Kind, v.Name, v.Path, v.Domain, v.Secure)
}
