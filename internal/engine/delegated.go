package engine

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/config"
	"github.com/open-rails/authkit/internal/errmodel"
	"github.com/open-rails/authkit/internal/jose"
	"github.com/open-rails/authkit/internal/ops"
	"github.com/open-rails/authkit/keys"
)

// MintDelegatedAccessToken signs a delegated access token as this deployment.
// A user actor mints for itself only, and every AuthKit-namespace permission
// in the grant must be held live on the root group (checkDelegatedGrant); the
// system may mint for any subject; machine actors may not mint. A user actor
// bound to a session (verify.ActorFromClaims) mints only while that session
// stands, and the token carries it (sid or device_key_id), so revoking the
// session cuts the delegated token off at every AuthKit permission check.
func (s *Engine) MintDelegatedAccessToken(ctx context.Context, actor iam.Actor, d iam.DelegatedAccess, opts ...ops.Option) (iam.Token, error) {
	if err := noOptions("MintDelegatedAccessToken", opts); err != nil {
		return iam.Token{}, err
	}
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

// delegatedTTL clamps a requested lifetime into the Config.Delegated bounds.
func (s *Engine) delegatedTTL(ttl time.Duration) time.Duration {
	c := s.cfg.Delegated
	if len(c.Audiences) == 0 {
		c.TTLFloor, c.TTLDefault, c.TTLCeiling = config.DefaultDelegatedTTLFloor, config.DefaultDelegatedTTLDefault, config.DefaultDelegatedTTLCeiling
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
	return s.actorAuthority(ctx, st, a, groupTarget{ID: rootID, Persona: iam.RootPersona()})
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
// attributes, a jti, at most one sender binding, and the minting session (sid
// or device_key_id) when there is one. The caller has authorized the grant
// and clamped p.TTL.
func mintDelegatedAccessToken(ctx context.Context, signer keys.Signer, issuer string, p iam.DelegatedAccess, session iam.SessionRef, now time.Time) (string, error) {
	if issuer == "" {
		return "", errors.New("issuer required")
	}
	if p.Subject == "" {
		return "", errors.New("delegated_sub required")
	}
	claims := map[string]any{
		"iss":           issuer,
		"iat":           now.Unix(),
		"exp":           now.Add(p.TTL).Unix(),
		"delegated_sub": p.Subject,
	}
	if len(p.Audiences) > 0 {
		claims["aud"] = p.Audiences
	}
	// Drop blanks so callers cannot smuggle empty permission strings.
	var perms []string
	for _, perm := range p.Permissions {
		if perm = strings.TrimSpace(perm); perm != "" {
			perms = append(perms, perm)
		}
	}
	if len(perms) > 0 {
		claims["permissions"] = perms
	}
	if len(p.Attributes) > 0 {
		claims["attributes"] = p.Attributes
	}
	// jti is always present, so a receiver can keep a revocation deny-list.
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
	switch {
	case p.CertificateThumbprint != "" && p.JWKThumbprint != "":
		return "", errors.New("delegated token must have only one sender binding")
	case p.CertificateThumbprint != "":
		if !jose.ValidThumbprint(p.CertificateThumbprint) {
			return "", errors.New("certificate thumbprint must be an unpadded base64url SHA-256")
		}
		claims[jose.ConfirmationClaim] = map[string]any{jose.CertificateThumbprintMember: p.CertificateThumbprint}
	case p.JWKThumbprint != "":
		if !jose.ValidThumbprint(p.JWKThumbprint) {
			return "", errors.New("JWK thumbprint must be an unpadded base64url SHA-256")
		}
		claims[jose.ConfirmationClaim] = map[string]any{jose.JWKThumbprintMember: p.JWKThumbprint}
	}
	if session.SessionID != "" {
		claims["sid"] = session.SessionID
	}
	if session.DeviceKeyID != "" {
		claims["device_key_id"] = session.DeviceKeyID
	}
	return jose.Sign(ctx, signer, jose.DelegatedAccessTokenType, claims)
}
