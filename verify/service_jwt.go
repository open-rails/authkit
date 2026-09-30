package verify

import (
	"context"
	"strings"
	"time"

	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/errmodel"
	"github.com/open-rails/authkit/internal/jose"
)

// ServiceJWTVerifyOption configures VerifyServiceJWT.
type ServiceJWTVerifyOption func(*serviceJWTConfig)

type serviceJWTConfig struct{ maxLifetime time.Duration }

// WithServiceJWTMaxLifetime caps the accepted lifetime (default 15m).
func WithServiceJWTMaxLifetime(d time.Duration) ServiceJWTVerifyOption {
	return func(c *serviceJWTConfig) { c.maxLifetime = d }
}

// VerifyServiceJWT verifies a service JWT (token_use=service) of a trusted
// issuer and returns its claims. It grants nothing: the host intersects the
// requested permissions with its own grants for the issuer and subject.
func (v *Verifier) VerifyServiceJWT(ctx context.Context, token string, opts ...ServiceJWTVerifyOption) (iam.ServiceJWTClaims, error) {
	cfg := serviceJWTConfig{maxLifetime: iam.DefaultServiceJWTLifetime}
	for _, opt := range opts {
		if opt != nil {
			opt(&cfg)
		}
	}
	if cfg.maxLifetime <= 0 {
		cfg.maxLifetime = iam.DefaultServiceJWTLifetime
	}
	mc, err := v.VerifyClaims(ctx, token)
	if err != nil {
		return iam.ServiceJWTClaims{}, err
	}
	issuer := strings.TrimSpace(jose.String(mc, "iss"))
	subject := strings.TrimSpace(jose.String(mc, "sub"))
	jti := strings.TrimSpace(jose.String(mc, "jti"))
	if issuer == "" || subject == "" || jti == "" || jose.String(mc, "token_use") != iam.ServiceJWTTokenUse ||
		strings.TrimSpace(jose.String(mc, "delegated_sub")) != "" {
		return iam.ServiceJWTClaims{}, iam.ErrInvalidServiceJWT
	}
	iat, ok := jose.Time(mc, "iat")
	if !ok {
		return iam.ServiceJWTClaims{}, errmodel.E(errmodel.CodeMissingIAT)
	}
	nbf, ok := jose.Time(mc, "nbf")
	if !ok {
		return iam.ServiceJWTClaims{}, errmodel.E(errmodel.CodeMissingNBF)
	}
	exp, _ := jose.Time(mc, "exp") // VerifyClaims required it
	if exp.Sub(iat) > cfg.maxLifetime {
		return iam.ServiceJWTClaims{}, errmodel.E(errmodel.CodeServiceJWTLifetimeExceeded)
	}
	permissions, err := permissionsClaim(mc)
	if err != nil {
		return iam.ServiceJWTClaims{}, err
	}
	return iam.ServiceJWTClaims{
		Issuer: issuer, Subject: subject, Audiences: jose.Audiences(mc),
		IssuedAt: iat.UTC(), NotBefore: nbf.UTC(), ExpiresAt: exp.UTC(), JTI: jti,
		TokenUse: iam.ServiceJWTTokenUse, Permissions: permissions,
	}, nil
}

// permissionsClaim is a strictly string-array permissions claim, blanks
// dropped; a non-string element is malformed.
func permissionsClaim(mc map[string]any) ([]string, error) {
	raw, ok := mc["permissions"]
	if !ok || raw == nil {
		return nil, nil
	}
	values, ok := raw.([]any)
	if !ok {
		return nil, errmodel.E(errmodel.CodeMalformedPermissions)
	}
	out := make([]string, 0, len(values))
	for _, value := range values {
		s, ok := value.(string)
		if !ok {
			return nil, errmodel.E(errmodel.CodeMalformedPermissions)
		}
		if s = strings.TrimSpace(s); s != "" {
			out = append(out, s)
		}
	}
	return out, nil
}
