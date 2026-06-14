package authhttp

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	jwt "github.com/golang-jwt/jwt/v5"
	core "github.com/open-rails/authkit/core"
)

// ServiceJWTPrincipal is the verified machine principal in a service JWT. The
// receiving host still owns authorization: intersect Permissions with its own
// server-side grants before allowing an action.
type ServiceJWTPrincipal struct {
	Issuer      string
	Subject     string
	Tenant      string
	Audiences   []string
	Permissions []string
	Resources   []core.ServiceTokenResource
	JTI         string
	ExpiresAt   time.Time
}

type serviceJWTPrincipalCtxKey struct{}

// ServiceJWTPrincipalFromContext returns the verified service-JWT principal
// attached by RequiredServiceJWT.
func ServiceJWTPrincipalFromContext(ctx context.Context) (ServiceJWTPrincipal, bool) {
	v, ok := ctx.Value(serviceJWTPrincipalCtxKey{}).(ServiceJWTPrincipal)
	return v, ok
}

func setServiceJWTPrincipal(ctx context.Context, p ServiceJWTPrincipal) context.Context {
	return context.WithValue(ctx, serviceJWTPrincipalCtxKey{}, p)
}

// ServiceJWTReplayChecker lets hosts reject already-seen jti values.
type ServiceJWTReplayChecker func(ctx context.Context, claims core.ServiceJWTClaims) error

type serviceJWTVerifyConfig struct {
	maxLifetime time.Duration
	replay      ServiceJWTReplayChecker
}

// ServiceJWTVerifyOption configures VerifyServiceJWT.
type ServiceJWTVerifyOption func(*serviceJWTVerifyConfig)

// WithServiceJWTMaxLifetime caps accepted service-JWT lifetime. Empty defaults
// to AuthKit's 15-minute service-JWT lifetime.
func WithServiceJWTMaxLifetime(d time.Duration) ServiceJWTVerifyOption {
	return func(c *serviceJWTVerifyConfig) { c.maxLifetime = d }
}

// WithServiceJWTReplayChecker installs an optional jti replay hook.
func WithServiceJWTReplayChecker(fn ServiceJWTReplayChecker) ServiceJWTVerifyOption {
	return func(c *serviceJWTVerifyConfig) { c.replay = fn }
}

// RequiredServiceJWT verifies a Bearer service JWT and attaches its principal.
// It is intentionally separate from Required so service JWTs do not become valid
// on ordinary user/delegated-token routes by accident.
func RequiredServiceJWT(v *Verifier, opts ...ServiceJWTVerifyOption) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			tokenStr := bearerToken(r.Header.Get("Authorization"))
			if tokenStr == "" {
				unauthorized(w, "missing_token")
				return
			}
			_, principal, err := v.VerifyServiceJWT(r.Context(), tokenStr, opts...)
			if err != nil {
				unauthorized(w, err.Error())
				return
			}
			next.ServeHTTP(w, r.WithContext(setServiceJWTPrincipal(r.Context(), principal)))
		})
	}
}

// VerifyServiceJWT verifies a first-party OIDC service JWT through the
// verifier's registered issuer/JWKS store and returns the requested
// permissions/resources. AuthKit does not grant those permissions; the host must
// intersect them with server-side grants for the issuer/subject/resource.
func (v *Verifier) VerifyServiceJWT(ctx context.Context, tokenStr string, opts ...ServiceJWTVerifyOption) (core.ServiceJWTClaims, ServiceJWTPrincipal, error) {
	cfg := serviceJWTVerifyConfig{maxLifetime: core.DefaultServiceJWTLifetime}
	for _, opt := range opts {
		if opt != nil {
			opt(&cfg)
		}
	}
	if cfg.maxLifetime <= 0 {
		cfg.maxLifetime = core.DefaultServiceJWTLifetime
	}

	mc, err := v.VerifyClaims(tokenStr)
	if err != nil {
		return core.ServiceJWTClaims{}, ServiceJWTPrincipal{}, err
	}
	claims, principal, err := v.serviceJWTClaimsFromMap(mc, cfg.maxLifetime)
	if err != nil {
		return core.ServiceJWTClaims{}, ServiceJWTPrincipal{}, err
	}
	if cfg.replay != nil {
		if err := cfg.replay(ctx, claims); err != nil {
			return core.ServiceJWTClaims{}, ServiceJWTPrincipal{}, err
		}
	}
	return claims, principal, nil
}

func (v *Verifier) serviceJWTClaimsFromMap(mc jwt.MapClaims, maxLifetime time.Duration) (core.ServiceJWTClaims, ServiceJWTPrincipal, error) {
	issuer := strings.TrimSpace(strClaim(mc, "iss"))
	subject := strings.TrimSpace(strClaim(mc, "sub"))
	tokenUse := strings.TrimSpace(strClaim(mc, "token_use"))
	jti := strings.TrimSpace(strClaim(mc, "jti"))
	if issuer == "" || subject == "" || tokenUse != core.ServiceJWTTokenUse || jti == "" {
		return core.ServiceJWTClaims{}, ServiceJWTPrincipal{}, core.ErrInvalidServiceJWT
	}
	if strings.TrimSpace(strClaim(mc, "delegated_sub")) != "" {
		return core.ServiceJWTClaims{}, ServiceJWTPrincipal{}, core.ErrInvalidServiceJWT
	}
	iatUnix, ok := toUnix(mc["iat"])
	if !ok {
		return core.ServiceJWTClaims{}, ServiceJWTPrincipal{}, errors.New("missing_iat")
	}
	nbfUnix, ok := toUnix(mc["nbf"])
	if !ok {
		return core.ServiceJWTClaims{}, ServiceJWTPrincipal{}, errors.New("missing_nbf")
	}
	expUnix, ok := toUnix(mc["exp"])
	if !ok {
		return core.ServiceJWTClaims{}, ServiceJWTPrincipal{}, errors.New("missing_exp")
	}
	iat := time.Unix(iatUnix, 0).UTC()
	nbf := time.Unix(nbfUnix, 0).UTC()
	exp := time.Unix(expUnix, 0).UTC()
	if exp.Sub(iat) > maxLifetime {
		return core.ServiceJWTClaims{}, ServiceJWTPrincipal{}, errors.New("service_jwt_lifetime_exceeded")
	}
	audiences := audSlice(mc["aud"])
	if len(audiences) == 0 {
		return core.ServiceJWTClaims{}, ServiceJWTPrincipal{}, errors.New("missing_audience")
	}
	permissions, err := stringArrayClaim(mc, "permissions")
	if err != nil {
		return core.ServiceJWTClaims{}, ServiceJWTPrincipal{}, err
	}
	if len(permissions) == 0 {
		permissions = scopeSlice(mc["scope"])
	}
	resources, err := serviceJWTResources(mc["resources"])
	if err != nil {
		return core.ServiceJWTClaims{}, ServiceJWTPrincipal{}, err
	}

	// Resolve the tenant from the VALIDATED issuer + audience. When several
	// tenants share an issuer string, the token's aud selects which one; an
	// ambiguous or unmatched binding fails closed so a token can never resolve to
	// the wrong tenant (C-1). The tenant identity rides in the issuer registry,
	// never in the token's own claims.
	tenantSlug, terr := v.tenantForIssuerAudience(issuer, mc["aud"])
	if terr != nil {
		return core.ServiceJWTClaims{}, ServiceJWTPrincipal{}, terr
	}
	claims := core.ServiceJWTClaims{
		Issuer: issuer, Subject: subject, Audiences: audiences,
		IssuedAt: iat, NotBefore: nbf, ExpiresAt: exp, JTI: jti,
		TokenUse: tokenUse, Permissions: permissions, Resources: resources,
		Scope: scopeSlice(mc["scope"]),
	}
	principal := ServiceJWTPrincipal{
		Issuer: issuer, Subject: subject, Tenant: tenantSlug,
		Audiences: audiences, Permissions: permissions, Resources: resources,
		JTI: jti, ExpiresAt: exp,
	}
	return claims, principal, nil
}

func audSlice(v any) []string {
	switch a := v.(type) {
	case string:
		if strings.TrimSpace(a) == "" {
			return nil
		}
		return []string{strings.TrimSpace(a)}
	case []any:
		out := make([]string, 0, len(a))
		for _, item := range a {
			if s, ok := item.(string); ok && strings.TrimSpace(s) != "" {
				out = append(out, strings.TrimSpace(s))
			}
		}
		return out
	case []string:
		out := make([]string, 0, len(a))
		for _, s := range a {
			if strings.TrimSpace(s) != "" {
				out = append(out, strings.TrimSpace(s))
			}
		}
		return out
	}
	return nil
}

func scopeSlice(v any) []string {
	switch s := v.(type) {
	case string:
		return strings.Fields(s)
	case []any:
		out := make([]string, 0, len(s))
		for _, item := range s {
			if v, ok := item.(string); ok && strings.TrimSpace(v) != "" {
				out = append(out, strings.TrimSpace(v))
			}
		}
		return out
	case []string:
		out := make([]string, 0, len(s))
		for _, v := range s {
			if strings.TrimSpace(v) != "" {
				out = append(out, strings.TrimSpace(v))
			}
		}
		return out
	}
	return nil
}

func stringArrayClaim(mc jwt.MapClaims, key string) ([]string, error) {
	raw, exists := mc[key]
	if !exists || raw == nil {
		return nil, nil
	}
	switch values := raw.(type) {
	case []any:
		out := make([]string, 0, len(values))
		for _, value := range values {
			s, ok := value.(string)
			if !ok {
				return nil, errors.New("malformed_permissions")
			}
			if strings.TrimSpace(s) != "" {
				out = append(out, strings.TrimSpace(s))
			}
		}
		return out, nil
	case []string:
		out := make([]string, 0, len(values))
		for _, value := range values {
			if strings.TrimSpace(value) != "" {
				out = append(out, strings.TrimSpace(value))
			}
		}
		return out, nil
	default:
		return nil, errors.New("malformed_permissions")
	}
}

func serviceJWTResources(v any) ([]core.ServiceTokenResource, error) {
	if v == nil {
		return nil, nil
	}
	raw, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	var resources []core.ServiceTokenResource
	if err := json.Unmarshal(raw, &resources); err != nil {
		return nil, err
	}
	for _, r := range resources {
		if strings.TrimSpace(r.Kind) == "" || strings.TrimSpace(r.ID) == "" {
			return nil, errors.New("invalid_resource")
		}
	}
	return resources, nil
}
