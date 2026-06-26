package verify

import (
	"context"
	"errors"
	"strings"
	"time"

	jwt "github.com/golang-jwt/jwt/v5"
	authkit "github.com/open-rails/authkit"
)

// ServiceJWTReplayChecker lets hosts reject already-seen jti values.
type ServiceJWTReplayChecker func(ctx context.Context, claims authkit.ServiceJWTClaims) error

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

// VerifyServiceJWT verifies a first-party OIDC service JWT through the
// verifier's registered issuer/JWKS store and returns the requested
// permissions. AuthKit does not grant those permissions; the host must
// intersect them with server-side grants for the issuer/subject/resource.
func (v *Verifier) VerifyServiceJWT(ctx context.Context, tokenStr string, opts ...ServiceJWTVerifyOption) (authkit.ServiceJWTClaims, error) {
	cfg := serviceJWTVerifyConfig{maxLifetime: authkit.DefaultServiceJWTLifetime}
	for _, opt := range opts {
		if opt != nil {
			opt(&cfg)
		}
	}
	if cfg.maxLifetime <= 0 {
		cfg.maxLifetime = authkit.DefaultServiceJWTLifetime
	}

	mc, err := v.VerifyClaims(tokenStr)
	if err != nil {
		return authkit.ServiceJWTClaims{}, err
	}
	claims, err := v.serviceJWTClaimsFromMap(mc, cfg.maxLifetime)
	if err != nil {
		return authkit.ServiceJWTClaims{}, err
	}
	if cfg.replay != nil {
		if err := cfg.replay(ctx, claims); err != nil {
			return authkit.ServiceJWTClaims{}, err
		}
	}
	return claims, nil
}

func (v *Verifier) serviceJWTClaimsFromMap(mc jwt.MapClaims, maxLifetime time.Duration) (authkit.ServiceJWTClaims, error) {
	issuer := strings.TrimSpace(strClaim(mc, "iss"))
	subject := strings.TrimSpace(strClaim(mc, "sub"))
	tokenUse := strings.TrimSpace(strClaim(mc, "token_use"))
	jti := strings.TrimSpace(strClaim(mc, "jti"))
	if issuer == "" || subject == "" || tokenUse != authkit.ServiceJWTTokenUse || jti == "" {
		return authkit.ServiceJWTClaims{}, authkit.ErrInvalidServiceJWT
	}
	if strings.TrimSpace(strClaim(mc, "delegated_sub")) != "" {
		return authkit.ServiceJWTClaims{}, authkit.ErrInvalidServiceJWT
	}
	iatUnix, ok := toUnix(mc["iat"])
	if !ok {
		return authkit.ServiceJWTClaims{}, errors.New("missing_iat")
	}
	nbfUnix, ok := toUnix(mc["nbf"])
	if !ok {
		return authkit.ServiceJWTClaims{}, errors.New("missing_nbf")
	}
	expUnix, ok := toUnix(mc["exp"])
	if !ok {
		return authkit.ServiceJWTClaims{}, errors.New("missing_exp")
	}
	iat := time.Unix(iatUnix, 0).UTC()
	nbf := time.Unix(nbfUnix, 0).UTC()
	exp := time.Unix(expUnix, 0).UTC()
	if exp.Sub(iat) > maxLifetime {
		return authkit.ServiceJWTClaims{}, errors.New("service_jwt_lifetime_exceeded")
	}
	audiences := audSlice(mc["aud"])
	if len(audiences) == 0 {
		return authkit.ServiceJWTClaims{}, errors.New("missing_audience")
	}
	permissions, err := stringArrayClaim(mc, "permissions")
	if err != nil {
		return authkit.ServiceJWTClaims{}, err
	}
	if len(permissions) == 0 {
		permissions = scopeSlice(mc["scope"])
	}

	match := v.matchIssuer(issuer)
	if match == nil {
		return authkit.ServiceJWTClaims{}, errors.New("bad_issuer")
	}
	claims := authkit.ServiceJWTClaims{
		Issuer: issuer, Subject: subject, Audiences: audiences,
		IssuedAt: iat, NotBefore: nbf, ExpiresAt: exp, JTI: jti,
		TokenUse: tokenUse, Permissions: permissions,
		Scope: scopeSlice(mc["scope"]),
	}
	return claims, nil
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
