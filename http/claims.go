package authhttp

import (
	"context"
	"encoding/json"
	"errors"
	"strings"

	core "github.com/open-rails/authkit/core"
)

// Claims is a typed view of authenticated user information attached by middleware.
type Claims struct {
	UserID          string
	Email           string
	EmailVerified   bool
	Username        string
	DiscordUsername string
	SessionID       string
	Roles           []string
	// GlobalRoles are the user's GLOBAL (platform-wide) roles, carried in the
	// `global_roles` claim in both single and multi-org mode. Use these for
	// global-admin authorization decisions.
	GlobalRoles []string
	Org         string
	// OrgRoles are the roles scoped to the org named in Org, carried in the
	// `org_roles` claim on org-scoped tokens. Use these for org-scoped authz.
	OrgRoles     []string
	Entitlements []string
	Issuer       string
	UserTier     string
	JTI          string

	// Delegated/federated fields. A delegated access token carries the external
	// actor in DelegatedSubject (claim `delegated_sub`) and the canonical target
	// resource account in Tenant (claim `tenant`). It never carries
	// `sub` (UserID stays empty), so the local-user gate does not apply.
	Tenant           string
	DelegatedSubject string

	// Attributes is the `attributes` claim of a delegated access token: an
	// object of issuer-provided policy metadata (e.g. {"tier":"cozy_free"}).
	// Values are kept as raw JSON so the receiving service can decode each into
	// its own typed schema. Nil when the claim is absent.
	Attributes map[string]json.RawMessage

	// TokenTyp is the JOSE `typ` header value. "access+jwt" identifies an
	// AuthKit access token; "delegated-access+jwt" identifies a delegated access
	// token.
	TokenTyp string

	// TokenType marks the credential class. Empty for ordinary user JWTs;
	// "service" for an Organization Access Token (OAT) acting AS THE ORG. A
	// service principal carries Org + Permissions but no UserID, so the live-user
	// ban/enrichment gate is skipped (there is no user to look up).
	TokenType string

	// Permissions are the app-defined permission strings a service principal
	// (OAT) carries directly — the PBAC grant. Empty for user principals, whose
	// authority is expressed as OrgRoles that the resource server expands to
	// permissions at request time. authkit treats permission strings as opaque.
	Permissions []string

	// Resources are opaque host-defined resource scopes carried by an
	// Organization Access Token. Empty means the OAT has no AuthKit-stored
	// resource constraints; resource-aware hosts decide whether to require them.
	Resources []core.OrgAccessTokenResource
}

// ServiceTokenType is the TokenType value carried by an Organization Access
// Token (OAT) — a machine credential that acts as the org, not a user.
const ServiceTokenType = "service"

// IsService reports whether these claims represent a service principal (an
// Organization Access Token), as opposed to a human user or delegated subject.
func (c Claims) IsService() bool {
	return strings.EqualFold(strings.TrimSpace(c.TokenType), ServiceTokenType)
}

// DelegatedPrincipal is the federated identity carried by a delegated access
// token: an external actor (DelegatedSubject) acting under a canonical target
// resource account (Tenant). The subject does NOT exist as a local user in the
// validating service — authorization is by issuer/resource-account trust plus
// Permissions, not local-user lookup.
type DelegatedPrincipal struct {
	Issuer           string
	Tenant           string
	DelegatedSubject string
	// Permissions are the resource-defined permission strings the receiving
	// service authorizes against its own catalog. This is the authority source.
	Permissions []string
	// Attributes is issuer-provided policy metadata (raw JSON values).
	Attributes map[string]json.RawMessage
	// JTI is the token identifier (`jti` claim), when present.
	JTI string
	// UserTier is the resolved tier, sourced from `attributes.tier`.
	UserTier string
}

// IsDelegated reports whether these claims represent a delegated principal
// (i.e. carry `delegated_sub` rather than a local `sub`).
func (c Claims) IsDelegated() bool {
	return strings.TrimSpace(c.DelegatedSubject) != ""
}

// IsDelegatedAccessToken reports whether these claims represent a delegated
// access token. The canonical signal is the `typ=delegated-access+jwt` JOSE
// header plus a delegated subject and no local user subject.
func (c Claims) IsDelegatedAccessToken() bool {
	return strings.EqualFold(strings.TrimSpace(c.TokenTyp), DelegatedAccessTokenType) &&
		strings.TrimSpace(c.UserID) == "" &&
		c.IsDelegated()
}

// Delegated returns the typed DelegatedPrincipal when the claims are delegated.
func (c Claims) Delegated() (DelegatedPrincipal, bool) {
	if !c.IsDelegated() {
		return DelegatedPrincipal{}, false
	}
	return DelegatedPrincipal{
		Issuer:           c.Issuer,
		Tenant:           strings.TrimSpace(c.Tenant),
		DelegatedSubject: c.DelegatedSubject,
		Permissions:      c.Permissions,
		Attributes:       c.Attributes,
		JTI:              c.JTI,
		UserTier:         c.UserTier,
	}, true
}

// DelegatedAccess is the canonical accessor for a delegated access token's
// principal. It returns the typed DelegatedPrincipal and true only when the
// claims are a delegated access token (see IsDelegatedAccessToken).
func (c Claims) DelegatedAccess() (DelegatedPrincipal, bool) {
	if !c.IsDelegatedAccessToken() {
		return DelegatedPrincipal{}, false
	}
	return c.Delegated()
}

// Attribute returns the raw JSON value of a single delegated-access-token
// attribute and whether it was present.
func (c Claims) Attribute(key string) (json.RawMessage, bool) {
	if c.Attributes == nil {
		return nil, false
	}
	v, ok := c.Attributes[key]
	return v, ok
}

// HasPermission reports whether the claims carry the exact permission string.
// Receiving services should layer scope semantics on top — string presence
// alone is not authorization.
func (c Claims) HasPermission(perm string) bool {
	for _, p := range c.Permissions {
		if p == perm {
			return true
		}
	}
	return false
}

func (c Claims) HasRole(role string) bool {
	for _, r := range c.Roles {
		if strings.EqualFold(r, role) {
			return true
		}
	}
	return false
}

func (c Claims) HasEntitlement(ent string) bool {
	for _, e := range c.Entitlements {
		if strings.EqualFold(e, ent) {
			return true
		}
	}
	return false
}

type claimsCtxKey struct{}

func setClaims(ctx context.Context, cl Claims) context.Context {
	return context.WithValue(ctx, claimsCtxKey{}, cl)
}

func ClaimsFromContext(ctx context.Context) (Claims, bool) {
	v := ctx.Value(claimsCtxKey{})
	if v == nil {
		return Claims{}, false
	}
	cl, ok := v.(Claims)
	return cl, ok
}

func getClaims(ctx context.Context) (Claims, error) {
	if cl, ok := ClaimsFromContext(ctx); ok {
		return cl, nil
	}
	return Claims{}, errors.New("unauthenticated")
}
