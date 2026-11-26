package config

import (
	"crypto/sha256"
	"encoding/hex"
	"net/url"
	"slices"
	"strings"

	"github.com/open-rails/authkit/iam"
)

// The host SPA's routes AuthKit links and redirects to, beneath FrontendURL.
const (
	OIDCReturnPath    = "/login/callback"
	VerifyPath        = "/verify"
	PasswordResetPath = "/reset"
	PasswordlessPath  = "/passwordless"
	InvitePath        = "/invite"
	SetupPath         = "/setup"
	AuthorizePath     = "/authorize"
)

// RootAPIPath is the JSON API's prefix for an issuer at its origin's root; an
// issuer with a path serves the API right beneath it.
const RootAPIPath = "/auth"

// Surface is where the HTTP surface lives, all of it from the issuer:
//
//	{Base}{API}/v1/...          JSON API
//	{Base}/oidc/{provider}/...  browser OIDC
//	{Base}/.well-known/jwks.json
type Surface struct {
	// Base is the issuer's path; "" at the root.
	Base string
	// API is the JSON API's prefix beneath Base, before APIVersion: "/auth"
	// at the root, "/" beneath a path.
	API string
	// PublicURL is the issuer without a trailing slash: where clients reach
	// Base, and what DPoP proofs and assertions name.
	PublicURL string
}

// HTTPSurface derives the surface from a normalized issuer.
func HTTPSurface(issuer string) Surface {
	u, _ := url.Parse(issuer)
	base, _ := MountPath("Issuer path", u.EscapedPath())
	s := Surface{Base: base, API: "/", PublicURL: u.Scheme + "://" + u.Host + base}
	if base == "" {
		s.API = RootAPIPath
	}
	return s
}

// RedisKeyPrefix namespaces one deployment's keys in a shared Redis.
func RedisKeyPrefix(issuer string) string {
	sum := sha256.Sum256([]byte(issuer))
	return "authkit:" + hex.EncodeToString(sum[:8]) + ":"
}

// FrontendLink is path beneath the frontend URL.
func FrontendLink(frontendURL, path string) string {
	return strings.TrimRight(frontendURL, "/") + path
}

// PasskeyRP is the WebAuthn relying party, from the frontend URL: its host
// names it and its origin runs the ceremonies.
type PasskeyRP struct {
	ID, Name string
	Origins  []string
}

// Passkeys derives the relying party from a normalized frontend URL.
func Passkeys(frontendURL string) PasskeyRP {
	u, _ := url.Parse(frontendURL)
	host := strings.ToLower(u.Hostname())
	return PasskeyRP{ID: host, Name: host, Origins: []string{u.Scheme + "://" + strings.ToLower(u.Host)}}
}

// TOTPIssuer is the service label authenticator apps show, the frontend's
// hostname, which password managers match. An IPv6 literal's colons, which
// the otpauth label reserves, become dots.
func TOTPIssuer(frontendURL string) string {
	u, _ := url.Parse(frontendURL)
	return strings.ReplaceAll(strings.ToLower(u.Hostname()), ":", ".")
}

// Mounted reports whether c serves group over HTTP. The opt-in features
// (passwordless sign-in, device keys, personal access tokens, invitations)
// are on exactly when their group is.
func Mounted(c Config, group iam.RouteGroup) bool {
	if c.HTTP == nil {
		return false
	}
	groups := c.HTTP.Groups
	if groups == nil {
		groups = iam.DefaultRouteGroups()
	}
	return slices.Contains(groups, group)
}

// InvitationsOn reports whether c issues and honours invitations: always
// headless (only the host's calls issue any), over HTTP with
// RouteInvitations.
func InvitationsOn(c Config) bool { return c.HTTP == nil || Mounted(c, iam.RouteInvitations) }
