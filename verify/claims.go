package verify

import (
	"context"
	"encoding/json"
	"strings"
	"time"

	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/errmodel"
	"github.com/open-rails/authkit/internal/ident"
	"github.com/open-rails/authkit/jwtkit"
	"github.com/open-rails/helpers/auth"
)

// Claims is a typed view of authenticated user information attached by middleware.
type Claims struct {
	// Subject is an external access token's subject. It is meaningful only with
	// Issuer; it never authorizes a lookup in the host's local user database.
	Subject string
	// UserID is populated only for an issuer explicitly trusted as IsLocal.
	UserID        string
	Email         string
	EmailVerified bool
	Username      string
	SessionID     string
	// DeviceKeyID is the AuthKit-issued machine credential that minted this
	// access token. It is present only on device-key tokens.
	DeviceKeyID     string
	Entitlements    []string
	AMR             []string
	ACR             string
	AuthTime        time.Time
	TwoFAEnrollment bool
	// MFAEnrolled reports whether the user has a usable second factor enrolled
	// (claim `mfa_enrolled`, stamped at issue from MFAStatus.Satisfied). The
	// Sensitive() gate uses it to require 2FA from users who have it, while never
	// blocking users who don't.
	MFAEnrolled bool
	Issuer      string
	UserTier    string
	JTI         string

	// A delegated access token carries the external delegated subject in
	// DelegatedSubject (claim `delegated_sub`). It never carries `sub` (UserID
	// stays empty), so the local-user gate does not apply.
	DelegatedSubject string

	// Attributes carries opaque app-specific JSON inline. AuthKit transports
	// these values; the consuming app owns their schema and semantics.
	// Reserved well-known keys: `tier` (opaque entitlement-tier string, surfaced
	// as UserTier) and `roles` (uuid array, surfaced as DelegatedRoles).
	// Everything else is free-form per consuming app. Values are kept as raw
	// JSON so the receiver decodes each into its own typed schema; nil when the
	// claim is absent.
	Attributes map[string]json.RawMessage

	// DelegatedRoles are the delegated subject's role UUIDs carried by a
	// delegated access token under `attributes.roles` (a JSON array of UUID strings). They are
	// extracted and validated at verify (malformed entries dropped, count
	// capped) and surfaced on DelegatedPrincipal.Roles. Downstream services use
	// them as e.g. budget-scope keys; authkit treats them as opaque strings.
	// Nil when absent.
	DelegatedRoles []string

	// ConfirmationCertificateSHA256 is the RFC 8705 `cnf.x5t#S256` binding of a
	// delegated token, already matched against the TLS peer leaf. Nil for an
	// unbound token.
	ConfirmationCertificateSHA256 *[32]byte
	// ConfirmationJWKThumbprintSHA256 is matched against this request's DPoP proof.
	ConfirmationJWKThumbprintSHA256 *[32]byte

	// TokenTyp is the JOSE `typ` header value. "access+jwt" identifies an
	// AuthKit user access token; "delegated-access+jwt" identifies a delegated
	// access token; "remote-application-access+jwt" identifies a remote
	// application access token.
	TokenTyp string

	// TokenType marks the credential class. Empty for ordinary user JWTs;
	// "api-key" for an API-key principal. An API-key principal carries
	// Permissions but no UserID, so the live-user ban/enrichment gate is skipped
	// (there is no user to look up).
	TokenType string
	// APIKeyID is the immutable credential ID returned by successful live key
	// resolution. It is never read from a JWT or the presented key's display name.
	APIKeyID string

	// Permissions are the app-defined permission strings an API-key principal
	// carries directly — the PBAC grant. Empty for user principals. authkit
	// treats permission strings as opaque.
	Permissions []string

	// RemoteApplicationID / RemoteApplicationSlug identify the remote_application
	// authenticated by a remote application access token. Populated ONLY for
	// stored self or delegated claims, resolved server-side from the validated
	// `iss` (never from a self-asserted token claim). The principal's Permissions
	// carry its STORED, assigned authority.
	RemoteApplicationID   string
	RemoteApplicationSlug string

	// Machine authority is resolved live from the receiving AuthKit deployment.
	// The group id and authority issuer fence ownership.
	PermissionGroupID              string
	PermissionGroupAuthorityIssuer string
	PermissionGroupPersona         string
}

// APIKeyPrincipalType is the TokenType value carried by an opaque API key: a
// machine credential, not a user.
const APIKeyPrincipalType = "api-key"

// RemoteApplicationTokenType is the TokenType value carried by a remote
// application access token: a remote_application acting AS ITSELF. Like an
// API-key principal it carries Permissions (its STORED authority) but no UserID;
// the live-user enrichment/ban gate is skipped (there is no user).
const RemoteApplicationTokenType = "remote_application"

// kind is the broad credential class of these claims. Unlike ActorFromClaims
// it also classifies an external user (Subject only) as a user.
func (c Claims) kind() iam.ActorKind {
	switch {
	case c.isAPIKey():
		return iam.ActorAPIKey
	case c.isRemoteApplication():
		return iam.ActorRemoteApplication
	case c.isDelegated():
		return iam.ActorDelegated
	case strings.TrimSpace(c.UserID) != "" || strings.TrimSpace(c.Subject) != "":
		return iam.ActorUser
	default:
		return ""
	}
}

// IsMachine reports whether these claims are an API key, remote-application
// or delegated credential rather than a user token.
func (c Claims) IsMachine() bool {
	k := c.kind()
	return k != "" && k != iam.ActorUser
}

// Identity is the provider-neutral identity of verified claims: the one
// principal shape AuthenticateRequest and the framework adapters return. ok is
// false when the claims name no subject under an issuer.
func (c Claims) Identity() (auth.Identity, bool) {
	i := auth.Identity{Issuer: c.Issuer, Email: c.Email, EmailVerified: c.EmailVerified, Username: c.Username, SessionID: c.SessionID}
	switch c.kind() {
	case iam.ActorUser:
		i.Kind, i.Subject = auth.KindUser, c.UserID
		if i.Subject == "" {
			i.Subject = c.Subject
		}
		if c.DeviceKeyID != "" {
			i.Kind, i.Subject = auth.KindDeviceKey, c.DeviceKeyID
		}
	case iam.ActorAPIKey:
		i.Kind, i.Subject, i.Issuer = auth.KindAPIKey, c.APIKeyID, c.PermissionGroupAuthorityIssuer
	case iam.ActorRemoteApplication:
		i.Kind, i.Subject = auth.KindRemoteApplication, c.RemoteApplicationID
	case iam.ActorDelegated:
		i.Kind, i.Subject = auth.KindDelegated, c.DelegatedSubject
	default:
		return auth.Identity{}, false
	}
	if strings.TrimSpace(i.Subject) == "" || strings.TrimSpace(i.Issuer) == "" {
		return auth.Identity{}, false
	}
	return i, true
}

// IsUser reports whether these claims represent a native human user.
func (c Claims) IsUser() bool {
	return c.kind() == iam.ActorUser && c.UserID != ""
}

func (c Claims) isAPIKey() bool {
	return strings.EqualFold(strings.TrimSpace(c.TokenType), APIKeyPrincipalType)
}

func (c Claims) isRemoteApplication() bool {
	return strings.EqualFold(strings.TrimSpace(c.TokenType), RemoteApplicationTokenType)
}

// DelegatedPrincipal is the identity carried by a delegated access token: an
// external actor (DelegatedSubject) whose authority is bounded by the VALIDATED
// Issuer plus Permissions. The subject does NOT exist as a local user in the
// validating service — authorization is by issuer trust plus Permissions, not
// local-user lookup.
type DelegatedPrincipal struct {
	// PermissionGroup is the live stored application's authority boundary.
	// Nil denotes explicitly trusted platform delegation. Missing fields in a
	// non-nil scope must deny; they never imply unbound authority.
	PermissionGroup *PermissionScope
	// Issuer is the validated token issuer the receiving service trusts.
	Issuer           string
	DelegatedSubject string
	// Permissions are the resource-defined permission strings the receiving
	// service authorizes against its own catalog. This is the authority source.
	Permissions []string
	// Attributes contains opaque, consumer-interpreted inline JSON values.
	// Reserved keys: tier (UserTier), roles (Roles).
	Attributes map[string]json.RawMessage
	// ConfirmationCertificateSHA256 is the verified certificate binding; nil
	// when the token is an unbound bearer.
	ConfirmationCertificateSHA256 *[32]byte
	// ConfirmationJWKThumbprintSHA256 is matched against this request's DPoP proof.
	ConfirmationJWKThumbprintSHA256 *[32]byte
	// JTI is the token identifier (`jti` claim), when present.
	JTI string
	// UserTier is the resolved tier, sourced from `attributes.tier`.
	UserTier string
	// Roles are the actor's role UUID strings, sourced from `attributes.roles`
	// (each validated as a well-formed UUID at verify; malformed entries are
	// dropped, count is capped). Kept as strings so consumers parse to uuid
	// without forcing a uuid dependency on the principal. Nil when absent.
	Roles []string
}

func (c Claims) isDelegated() bool {
	return strings.TrimSpace(c.DelegatedSubject) != ""
}

// IsDelegatedAccessToken reports whether these claims represent a delegated
// access token. The canonical signal is the `typ=delegated-access+jwt` JOSE
// header plus a delegated subject and no local user subject.
func (c Claims) IsDelegatedAccessToken() bool {
	return strings.EqualFold(strings.TrimSpace(c.TokenTyp), jwtkit.DelegatedAccessTokenType) &&
		strings.TrimSpace(c.UserID) == "" &&
		c.isDelegated()
}

// Delegated returns the typed DelegatedPrincipal when the claims are delegated.
func (c Claims) Delegated() (DelegatedPrincipal, bool) {
	if !c.isDelegated() {
		return DelegatedPrincipal{}, false
	}
	var scope *PermissionScope
	if c.BoundToPermissionGroup() {
		scope = &PermissionScope{GroupID: c.PermissionGroupID, AuthorityIssuer: c.PermissionGroupAuthorityIssuer, Persona: ident.Persona(c.PermissionGroupPersona)}
	}
	return DelegatedPrincipal{
		PermissionGroup:                 scope,
		Issuer:                          c.Issuer,
		DelegatedSubject:                c.DelegatedSubject,
		Permissions:                     c.Permissions,
		Attributes:                      c.Attributes,
		ConfirmationCertificateSHA256:   c.ConfirmationCertificateSHA256,
		ConfirmationJWKThumbprintSHA256: c.ConfirmationJWKThumbprintSHA256,
		JTI:                             c.JTI,
		UserTier:                        c.UserTier,
		Roles:                           c.DelegatedRoles,
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

// Attribute returns one opaque JSON value and whether it is present.
func (c Claims) Attribute(key string) (json.RawMessage, bool) {
	if c.Attributes == nil {
		return nil, false
	}
	v, ok := c.Attributes[key]
	return v, ok
}

// BoundToPermissionGroup reports whether these claims carry an owning
// permission-group binding (#248) — true for machine principals (API keys,
// remote-application access tokens) whose authority was resolved server-side
// from a specific group instance, including stored application delegation.
// Explicit platform delegation and user identity have no such binding.
func (c Claims) BoundToPermissionGroup() bool {
	return c.TokenType == APIKeyPrincipalType || c.TokenType == RemoteApplicationTokenType || c.RemoteApplicationID != "" ||
		c.PermissionGroupID != "" || c.PermissionGroupAuthorityIssuer != "" || c.PermissionGroupPersona != ""
}

// PermissionGroupAllows compares immutable ownership. Missing binding fields
// on a machine principal deny; an old spelling cannot transfer authority.
func (c Claims) PermissionGroupAllows(scope PermissionScope) bool {
	if !c.BoundToPermissionGroup() {
		return true
	}
	return c.PermissionGroupID != "" && scope.GroupID != "" && c.PermissionGroupID == scope.GroupID &&
		c.PermissionGroupAuthorityIssuer != "" && c.PermissionGroupAuthorityIssuer == scope.AuthorityIssuer &&
		c.PermissionGroupPersona != "" && ident.Persona(c.PermissionGroupPersona) == scope.Persona
}

// HasPermission reports whether the claims carry a permission token covering
// the requested concrete permission.
func (c Claims) HasPermission(perm iam.Perm) bool {
	for _, p := range c.Permissions {
		if perm.Matches(ident.Perm(p)) {
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

func (c Claims) HasAMR(method string) bool {
	for _, m := range c.AMR {
		if strings.EqualFold(strings.TrimSpace(m), strings.TrimSpace(method)) {
			return true
		}
	}
	return false
}

func (c Claims) AuthenticatedWithin(maxAge time.Duration) bool {
	if maxAge <= 0 || c.AuthTime.IsZero() {
		return false
	}
	now := time.Now()
	return !c.AuthTime.After(now) && now.Sub(c.AuthTime) <= maxAge
}

type claimsCtxKey struct{}

func SetClaims(ctx context.Context, cl Claims) context.Context {
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

// IdentityFromContext is the verified caller's provider-neutral identity
// (user, device key, API key, remote application or delegated principal).
func IdentityFromContext(ctx context.Context) (auth.Identity, bool) {
	cl, ok := ClaimsFromContext(ctx)
	if !ok {
		return auth.Identity{}, false
	}
	return cl.Identity()
}

func GetClaims(ctx context.Context) (Claims, error) {
	if cl, ok := ClaimsFromContext(ctx); ok {
		return cl, nil
	}
	return Claims{}, errmodel.E(errmodel.CodeUnauthenticated)
}
