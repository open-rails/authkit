package authhttp

import (
	"context"
	"errors"
	"strings"
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

	// Delegated/federated fields. A delegated platform token carries the
	// external user in DelegatedSubject (claim `delegated_sub`) and the
	// federated org in Tenant (claim `tenant`, falling back to `org`). It never
	// carries `sub` (UserID stays empty), so the local-user gate does not apply.
	Tenant           string
	DelegatedSubject string

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
}

// ServiceTokenType is the TokenType value carried by an Organization Access
// Token (OAT) — a machine credential that acts as the org, not a user.
const ServiceTokenType = "service"

// IsService reports whether these claims represent a service principal (an
// Organization Access Token), as opposed to a human user or delegated subject.
func (c Claims) IsService() bool {
	return strings.EqualFold(strings.TrimSpace(c.TokenType), ServiceTokenType)
}

// DelegatedPrincipal is the federated identity carried by a delegated platform
// token: an external user (DelegatedSubject) acting under a federated org
// (Tenant). The subject does NOT exist as a local user in the validating
// service — authorization is by tenant/issuer trust, not local-user lookup.
type DelegatedPrincipal struct {
	Tenant           string
	DelegatedSubject string
	UserTier         string
	Roles            []string
	Issuer           string
}

// IsDelegated reports whether these claims represent a delegated platform
// principal (i.e. carry `delegated_sub` rather than a local `sub`).
func (c Claims) IsDelegated() bool {
	return strings.TrimSpace(c.DelegatedSubject) != ""
}

// Delegated returns the typed DelegatedPrincipal when the claims are delegated.
func (c Claims) Delegated() (DelegatedPrincipal, bool) {
	if !c.IsDelegated() {
		return DelegatedPrincipal{}, false
	}
	tenant := strings.TrimSpace(c.Tenant)
	if tenant == "" {
		tenant = strings.TrimSpace(c.Org)
	}
	roles := c.Roles
	if len(roles) == 0 {
		roles = c.OrgRoles
	}
	return DelegatedPrincipal{
		Tenant:           tenant,
		DelegatedSubject: c.DelegatedSubject,
		UserTier:         c.UserTier,
		Roles:            roles,
		Issuer:           c.Issuer,
	}, true
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
