package engine

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	jwt "github.com/golang-jwt/jwt/v5"
	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/errmodel"
	"github.com/open-rails/authkit/jwtkit"
)

// MintDelegatedAccessToken signs a delegated access token as this deployment.
// A user actor mints for itself only, and every AuthKit-namespace permission
// in the grant must be held live on the root group (checkDelegatedGrant); the
// system may mint for any subject; machine actors may not mint. A user actor
// bound to a session (verify.ActorFromClaims) mints only while that session
// stands, and the token carries it (sid or device_key_id), so revoking the
// session cuts the delegated token off at every AuthKit permission check.
func (s *Engine) MintDelegatedAccessToken(ctx context.Context, actor iam.Actor, d iam.DelegatedAccess) (iam.Token, error) {
	if err := requireActor(actor); err != nil {
		return iam.Token{}, err
	}
	d.Subject = strings.TrimSpace(d.Subject)
	switch actor.Kind() {
	case iam.ActorSystem:
		if d.Subject == "" {
			return iam.Token{}, fmt.Errorf("%w: delegated subject required", errmodel.E(errmodel.CodeInvalidRequest))
		}
	case iam.ActorUser:
		self, _ := canonicalUUID(actor.ID())
		if d.Subject == "" {
			d.Subject = self
		}
		if subject, _ := canonicalUUID(d.Subject); self == "" || subject != self {
			return iam.Token{}, iam.ErrInsufficientAuthority
		}
		d.Subject = self
		if err := s.checkDelegatedGrant(ctx, actor, d.Permissions); err != nil {
			return iam.Token{}, err
		}
	default:
		return iam.Token{}, iam.ErrInsufficientAuthority
	}
	signer := s.keys.ActiveSigner()
	if signer == nil {
		return iam.Token{}, iam.ErrSigningNotConfigured
	}
	d.TTL = s.delegatedTTL(d.TTL)
	now := time.Now()
	session, _ := actor.Session()
	token, err := mintDelegatedAccessToken(ctx, signer, strings.TrimSpace(s.cfg.Token.Issuer), d, session, now)
	if err != nil {
		return iam.Token{}, err
	}
	return iam.Token{Value: token, ExpiresAt: now.Add(d.TTL)}, nil
}

// delegatedTTL clamps a requested lifetime into the Config.Delegated bounds,
// or the default bounds when the mint route is off.
func (s *Engine) delegatedTTL(ttl time.Duration) time.Duration {
	c := s.cfg.Delegated
	if c.TTLDefault == 0 {
		c.TTLFloor, c.TTLDefault, c.TTLCeiling = defaultDelegatedTTLFloor, defaultDelegatedTTLDefault, defaultDelegatedTTLCeiling
	}
	switch {
	case ttl <= 0:
		return c.TTLDefault
	case ttl < c.TTLFloor:
		return c.TTLFloor
	case ttl > c.TTLCeiling:
		return c.TTLCeiling
	}
	return ttl
}

// checkDelegatedGrant refuses a delegated grant carrying AuthKit authority the
// user does not hold now, and a user who is not live (nor, when bound, their
// session). Delegated permissions are scope-free, so one in an AuthKit
// persona's namespace must be held on the root group; the host's own
// vocabulary is the host's decision.
func (s *Engine) checkDelegatedGrant(ctx context.Context, user iam.Actor, permissions []string) error {
	auth, err := s.rootAuthority(ctx, user)
	if err != nil {
		return err
	}
	for _, perm := range permissions {
		if !s.delegatedPermissionHeld(auth, strings.TrimSpace(perm)) {
			return iam.ErrDelegationRefused
		}
	}
	return nil
}

// rootAuthority is a's authority on the root group (rule ACTOR).
func (s *Engine) rootAuthority(ctx context.Context, a iam.Actor) (authority, error) {
	if err := s.requirePG(); err != nil {
		return authority{}, err
	}
	st := s.groupStore()
	rootID, err := s.rootGroup(ctx, st)
	if err != nil {
		return authority{}, err
	}
	return s.actorAuthority(ctx, st, a, groupTarget{ID: rootID, Persona: iam.RootPersona})
}

func (s *Engine) delegatedPermissionHeld(auth authority, perm string) bool {
	namespace, _, _ := strings.Cut(perm, ":")
	sch := s.groupSchemaOrDefault()
	if _, ok := sch.PersonaNamed(namespace); !ok && namespace != "*" {
		return true
	}
	p, known := sch.Permission(perm)
	return known && auth.covers(p)
}

// mintDelegatedAccessToken signs a canonical delegated access token: typ
// delegated-access+jwt, delegated_sub and never sub, permissions,
// attributes (roles ride under attributes.roles), a jti, at most one sender
// binding, and the minting session (sid or device_key_id) when there is one.
// The caller has authorized the grant and clamped p.TTL.
func mintDelegatedAccessToken(ctx context.Context, signer jwtkit.Signer, issuer string, p iam.DelegatedAccess, session iam.SessionRef, now time.Time) (string, error) {
	if signer == nil {
		return "", errors.New("signer required")
	}
	if issuer == "" {
		return "", errors.New("issuer required")
	}
	if p.Subject == "" {
		return "", errors.New("delegated_sub required")
	}
	claims := jwt.MapClaims{
		"iss":           issuer,
		"iat":           now.Unix(),
		"exp":           now.Add(p.TTL).Unix(),
		"delegated_sub": p.Subject,
	}
	if len(p.Audiences) > 0 {
		claims["aud"] = p.Audiences
	}
	if len(p.Permissions) > 0 {
		// Copy + drop empties so callers can't smuggle blank permission strings.
		perms := make([]string, 0, len(p.Permissions))
		for _, perm := range p.Permissions {
			if s := strings.TrimSpace(perm); s != "" {
				perms = append(perms, s)
			}
		}
		if len(perms) > 0 {
			claims["permissions"] = perms
		}
	}
	// Merge the typed Roles convenience into attributes.roles (typed field wins
	// over any Attributes["roles"] the caller also set). Drop blanks so callers
	// can't smuggle empty role strings.
	attributes := p.Attributes
	if len(p.Roles) > 0 {
		roles := make([]string, 0, len(p.Roles))
		for _, r := range p.Roles {
			if s := strings.TrimSpace(r); s != "" {
				roles = append(roles, s)
			}
		}
		if len(roles) > 0 {
			if attributes == nil {
				attributes = make(map[string]any, 1)
			} else {
				// Copy so we don't mutate the caller's map.
				cp := make(map[string]any, len(attributes)+1)
				for k, vv := range attributes {
					cp[k] = vv
				}
				attributes = cp
			}
			attributes["roles"] = roles
		}
	}
	if len(attributes) > 0 {
		claims["attributes"] = attributes
	}
	// `jti` is ALWAYS present: a receiver can only gate a revocation deny-list
	// on the claim if every delegated token authkit signs carries one. An
	// explicit p.JTI wins; otherwise mint a fresh uuidv7.
	jti := strings.TrimSpace(p.JTI)
	if jti == "" {
		var err error
		if jti, err = newUUIDV7String(); err != nil {
			return "", fmt.Errorf("delegated jti: %w", err)
		}
	}
	claims["jti"] = jti
	if !p.NotBefore.IsZero() {
		claims["nbf"] = p.NotBefore.Unix()
	}
	if p.ConfirmationCertificateSHA256 != nil && p.ConfirmationJWKThumbprintSHA256 != nil {
		return "", errors.New("delegated token must have only one sender binding")
	}
	if p.ConfirmationJWKThumbprintSHA256 != nil {
		claims[jwtkit.ConfirmationClaim] = map[string]any{jwtkit.JWKThumbprintMember: jwtkit.CertificateThumbprint(*p.ConfirmationJWKThumbprintSHA256)}
	}
	if p.ConfirmationCertificateSHA256 != nil {
		claims[jwtkit.ConfirmationClaim] = jwtkit.ConfirmationClaimValue(*p.ConfirmationCertificateSHA256)
	}
	if session.SessionID != "" {
		claims["sid"] = session.SessionID
	}
	if session.DeviceKeyID != "" {
		claims["device_key_id"] = session.DeviceKeyID
	}
	// Invariant: a delegated access token must never carry `sub`.
	delete(claims, "sub")

	return jwtkit.SignWithType(ctx, signer, claims, jwtkit.DelegatedAccessTokenType, true)
}
