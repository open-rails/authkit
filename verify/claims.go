package verify

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/open-rails/authkit/authbase"
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
	Entitlements    []string
	AMR             []string
	ACR             string
	AuthTime        time.Time
	TwoFAEnrollment bool
	Issuer          string
	UserTier        string
	JTI             string

	// A delegated access token carries the external delegated subject in
	// DelegatedSubject (claim `delegated_sub`). It never carries `sub` (UserID
	// stays empty), so the local-user gate does not apply.
	DelegatedSubject string

	// Attributes is the `attributes` claim of a delegated access token: the
	// canonical app-specific ESCAPE HATCH (#75). It is an object of issuer-
	// asserted, NAMESPACED, OPAQUE key/values that AuthKit transports and
	// optionally shape-validates (WithAttributesPolicy) but NEVER interprets —
	// the semantics belong to the consuming app. Each value is in one of two
	// modes (see Attribute / AttributeIsReference):
	//   INLINE    — the value carries the full definition, e.g.
	//               {"tier":{"endpoints":[...],"caps":[...]}}.
	//   REFERENCE — the value is a short JSON string key, e.g. {"tier":"tier-1"},
	//               resolved against a definition the remote_application
	//               registered ahead of time (resolve via the attribute-def
	//               registry, or opt-in verify-time hydration).
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
	// Nil when absent. Distinct from the native-user Roles claim, which a
	// delegated token never carries.
	DelegatedRoles []string

	// TokenTyp is the JOSE `typ` header value. "access+jwt" identifies an
	// AuthKit user access token; "delegated-access+jwt" identifies a delegated
	// access token; "remote-application-access+jwt" identifies a remote
	// application access token.
	TokenTyp string

	// TokenType marks the credential class. Empty for ordinary user JWTs;
	// "service" for an API-key service principal. A service principal carries
	// Permissions but no UserID, so the live-user ban/enrichment gate is skipped
	// (there is no user to look up).
	TokenType string

	// Permissions are the app-defined permission strings a service principal
	// carries directly — the PBAC grant. Empty for user principals. authkit
	// treats permission strings as opaque.
	Permissions []string

	// Resources are opaque host-defined resource scopes carried by an
	// API key. Empty means the service principal has no AuthKit-stored
	// resource constraints; resource-aware hosts decide whether to require them.
	Resources []authbase.APIKeyResource

	// RemoteApplicationID / RemoteApplicationSlug identify the remote_application
	// authenticated by a remote application access token. Populated ONLY for
	// RemoteApplicationTokenType claims, resolved server-side from the validated
	// `iss` (never from a self-asserted token claim). The principal's Permissions
	// carry its STORED, assigned authority.
	RemoteApplicationID   string
	RemoteApplicationSlug string
}

// ServicePrincipalType is the TokenType value carried by an opaque API key: a
// machine credential, not a user.
const ServicePrincipalType = "service"

// RemoteApplicationTokenType is the TokenType value carried by a remote
// application access token: a remote_application acting AS ITSELF. Like a
// service principal it carries Permissions (its STORED authority) but no UserID;
// the live-user enrichment/ban gate is skipped (there is no user).
const RemoteApplicationTokenType = "remote_application"

// IsService reports whether these claims represent a service principal, as
// opposed to a human user or delegated subject.
func (c Claims) IsService() bool {
	return strings.EqualFold(strings.TrimSpace(c.TokenType), ServicePrincipalType)
}

// IsRemoteApplication reports whether these claims represent a remote
// application authenticated via a remote application access token.
func (c Claims) IsRemoteApplication() bool {
	return strings.EqualFold(strings.TrimSpace(c.TokenType), RemoteApplicationTokenType)
}

// DelegatedPrincipal is the identity carried by a delegated access token: an
// external actor (DelegatedSubject) whose authority is bounded by the VALIDATED
// Issuer plus Permissions. The subject does NOT exist as a local user in the
// validating service — authorization is by issuer trust plus Permissions, not
// local-user lookup.
type DelegatedPrincipal struct {
	// Issuer is the validated token issuer the receiving service trusts.
	Issuer           string
	DelegatedSubject string
	// Permissions are the resource-defined permission strings the receiving
	// service authorizes against its own catalog. This is the authority source.
	Permissions []string
	// Attributes is the issuer-asserted escape-hatch bag (#75): namespaced,
	// OPAQUE, consumer-interpreted key/values, each INLINE or REFERENCE (see
	// Claims.Attributes / Claims.AttributeReference). Reserved keys: `tier`
	// (-> UserTier) and `roles` (-> Roles). Raw JSON values.
	Attributes map[string]json.RawMessage
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
		DelegatedSubject: c.DelegatedSubject,
		Permissions:      c.Permissions,
		Attributes:       c.Attributes,
		JTI:              c.JTI,
		UserTier:         c.UserTier,
		Roles:            c.DelegatedRoles,
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
// attribute and whether it was present. The value is opaque (#75): the caller
// decides whether it is an INLINE definition (a JSON object/array) or a
// REFERENCE (a JSON string key) — see AttributeIsReference / AttributeReference.
func (c Claims) Attribute(key string) (json.RawMessage, bool) {
	if c.Attributes == nil {
		return nil, false
	}
	v, ok := c.Attributes[key]
	return v, ok
}

// AttributeReference reports whether attribute `key` is in REFERENCE mode (a
// JSON string the consumer resolves against the remote_application's registered
// definition) and returns the reference key. ok is false for INLINE values
// (objects/arrays/other) or an absent key. This is the ref-vs-inline detector
// the consumer uses before resolving against the attribute-def registry.
func (c Claims) AttributeReference(key string) (ref string, ok bool) {
	raw, present := c.Attribute(key)
	if !present {
		return "", false
	}
	if err := json.Unmarshal(raw, &ref); err != nil {
		return "", false // not a JSON string => INLINE
	}
	return ref, true
}

// AttributeIsReference reports whether attribute `key` is a REFERENCE (JSON
// string) rather than an INLINE definition. Convenience over AttributeReference.
func (c Claims) AttributeIsReference(key string) bool {
	_, ok := c.AttributeReference(key)
	return ok
}

// HasPermission reports whether the claims carry a permission token covering
// the requested concrete permission.
func (c Claims) HasPermission(perm string) bool {
	for _, p := range c.Permissions {
		if authbase.PermissionTokenCovers(p, perm) {
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

func GetClaims(ctx context.Context) (Claims, error) {
	if cl, ok := ClaimsFromContext(ctx); ok {
		return cl, nil
	}
	return Claims{}, errors.New("unauthenticated")
}
