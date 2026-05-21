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
	Org             string
	OrgRoles        []string
	Entitlements    []string
	Issuer          string
	UserTier        string
	JTI             string

	// Delegated/federated fields. A delegated platform token carries the
	// external user in DelegatedSubject (claim `delegated_sub`) and the
	// federated org in Tenant (claim `tenant`, falling back to `org`). It never
	// carries `sub` (UserID stays empty), so the local-user gate does not apply.
	Tenant           string
	DelegatedSubject string
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
