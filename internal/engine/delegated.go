package engine

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	jwt "github.com/golang-jwt/jwt/v5"
	"github.com/open-rails/authkit/documents"
	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/errmodel"
	"github.com/open-rails/authkit/jwtkit"
)

// MintDelegatedAccessToken signs a delegated access token as this deployment.
// A user actor mints for itself only, and every AuthKit-namespace permission
// in the grant must be held live on the root group (checkDelegatedGrant); the
// system may mint for any subject; machine actors may not mint. Published
// documents are stamped into every token.
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
		if err := s.checkDelegatedGrant(ctx, d.Subject, d.Permissions); err != nil {
			return iam.Token{}, err
		}
	default:
		return iam.Token{}, iam.ErrInsufficientAuthority
	}
	signer := s.keys.ActiveSigner()
	if signer == nil {
		return iam.Token{}, iam.ErrSigningNotConfigured
	}
	refs, providers, err := s.delegatedDocuments(d.Documents)
	if err != nil {
		return iam.Token{}, err
	}
	d.Documents = refs
	d.TTL = s.delegatedTTL(d.TTL)
	now := time.Now()
	token, err := mintDelegatedAccessToken(ctx, signer, strings.TrimSpace(s.cfg.Token.Issuer), d, now)
	if err != nil {
		return iam.Token{}, err
	}
	if len(providers) > 0 {
		kid, err := signingKID(token)
		if err != nil {
			return iam.Token{}, errmodel.E(errmodel.CodeDelegatedDocumentUnavailable, errmodel.WithCause(err))
		}
		if err := reconcileDocumentKeys(ctx, providers, refs, kid); err != nil {
			return iam.Token{}, err
		}
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
// user does not hold now. Delegated permissions are scope-free, so one in an
// AuthKit persona's namespace must be held on the root group by a live user;
// the host's own vocabulary is the host's decision.
func (s *Engine) checkDelegatedGrant(ctx context.Context, userID string, permissions []string) error {
	auth, err := s.rootUserAuthority(ctx, userID)
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

// rootUserAuthority is a live user's authority on the root group. A deleted,
// reserved or banned user is ErrInsufficientAuthority.
func (s *Engine) rootUserAuthority(ctx context.Context, userID string) (authority, error) {
	if err := s.requirePG(); err != nil {
		return authority{}, err
	}
	st := s.groupStore()
	rootID, err := s.rootGroup(ctx, st)
	if err != nil {
		return authority{}, err
	}
	return s.actorAuthority(ctx, st, iam.UserActor(userID), groupTarget{ID: rootID, Persona: iam.RootPersona})
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

// signingKID is the kid protected header of a compact JWS this engine signed.
func signingKID(token string) (string, error) {
	header, _, ok := strings.Cut(token, ".")
	if !ok {
		return "", errors.New("token is not a compact JWS")
	}
	raw, err := base64.RawURLEncoding.DecodeString(header)
	if err != nil {
		return "", errors.New("token has a malformed protected header")
	}
	var h struct {
		KeyID string `json:"kid"`
	}
	if err := json.Unmarshal(raw, &h); err != nil || strings.TrimSpace(h.KeyID) == "" {
		return "", errors.New("token signing key id is unavailable")
	}
	return strings.TrimSpace(h.KeyID), nil
}

// mintDelegatedAccessToken signs a canonical delegated access token: typ
// delegated-access+jwt, delegated_sub and never sub, permissions, documents,
// attributes (roles ride under attributes.roles), a jti and at most one sender
// binding. The caller has authorized the grant and clamped p.TTL.
func mintDelegatedAccessToken(ctx context.Context, signer jwtkit.Signer, issuer string, p iam.DelegatedAccess, now time.Time) (string, error) {
	if signer == nil {
		return "", errors.New("signer required")
	}
	if issuer == "" {
		return "", errors.New("issuer required")
	}
	if p.Subject == "" {
		return "", errors.New("delegated_sub required")
	}
	references, err := documents.NormalizeReferences(p.Documents)
	if err != nil {
		return "", err
	}
	if _, shadowsTopLevel := p.Attributes["documents"]; shadowsTopLevel {
		return "", fmt.Errorf("%w: attributes.documents is reserved", documents.ErrReservedAttribute)
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
	if len(references) > 0 {
		claims["documents"] = references
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
	// Invariant: a delegated access token must never carry `sub`.
	delete(claims, "sub")

	return jwtkit.SignWithType(ctx, signer, claims, jwtkit.DelegatedAccessTokenType, true)
}
