package verify

import (
	"context"
	"encoding/json"
	"net/http"
	"reflect"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/ident"
	"github.com/open-rails/helpers/auth"
)

// Claims is a verified credential: what the middleware stores in the request
// context. Kind says which fields apply.
type Claims struct {
	// Kind is the credential class: iam.ActorUser, iam.ActorDelegated or
	// (a resource access token whose sub is its client_id)
	// iam.ActorOAuthClient for a token, and from *authkit.Client also
	// iam.ActorAPIKey and iam.ActorRemoteApplication.
	Kind iam.ActorKind
	// JOSEType is the token's typ header ("access+jwt",
	// "delegated-access+jwt", "remote-application-access+jwt", "at+jwt");
	// empty for an API key.
	JOSEType string
	// Issuer is the validated iss.
	Issuer string

	// UserID is a local user: set only for an issuer registered IsLocal.
	UserID string
	// Subject is another issuer's user, or a resource access token's sub
	// (its user, or its client acting for itself) whichever issuer minted it.
	// It is meaningful only with Issuer and never names a local user.
	Subject string
	// DelegatedSubject is a delegated token's delegated_sub, whose authority
	// is Permissions: the user who minted a token of this deployment, else an
	// external actor. It never sets UserID.
	DelegatedSubject string
	// SessionID (sid) or DeviceKeyID names the sign-in a native token, or a
	// delegated token AuthKit minted from one, was minted from; the session
	// check refuses the token once it is revoked.
	SessionID   string
	DeviceKeyID string
	// APIKeyID is the key an API-key credential resolved to.
	APIKeyID string
	// RemoteApplicationID is the stored application behind a remote
	// application token or its delegation, resolved from the validated iss.
	RemoteApplicationID string
	// Group binds a machine credential's authority to the group it was
	// granted in: set for API keys, remote applications and their
	// delegations; nil otherwise.
	Group *PermissionScope

	// Permissions are the credential's permission strings: an API key's or
	// application's stored grants, a delegated token's grant (bounded by the
	// application's stored ceiling when an application issued it), or a
	// resource access token's grant for its audience (the user's permissions
	// within the resource server's ceiling at mint). Native user tokens carry
	// none; their authority is read live (Can).
	Permissions []string
	// Attributes is the attributes claim, each value raw JSON for the
	// consuming service to decode; AuthKit assigns no key a meaning.
	Attributes map[string]json.RawMessage
	// Entitlements is the issuer's token-time entitlements snapshot.
	Entitlements []string
	// RootRole is the user's root-group role at mint ("root:admin"), for
	// display only: UI and content visibility without a database call. It is
	// stale up to the token lifetime and never authorizes anything; every
	// permission check reads the role live.
	RootRole string

	Email         string
	EmailVerified bool
	Username      string

	// AMR, ACR and AuthTime describe the sign-in the token carries.
	AMR      []string
	ACR      string
	AuthTime time.Time
	// TwoFAEnrollment marks a token that reaches only AuthKit's 2FA
	// enrollment routes; every verifier refuses it elsewhere.
	TwoFAEnrollment bool
	// MFAEnrolled is whether the user had a usable second factor at mint.
	MFAEnrolled bool
	JTI         string

	// ClientID is the OAuth client a resource access token was issued to;
	// Scopes its granted scopes and Roles the user's role names at mint, for
	// display only.
	ClientID string
	Scopes   []string
	Roles    []string

	// CertificateThumbprint (cnf x5t#S256) or JWKThumbprint (cnf jkt) is a
	// delegated or resource token's sender binding, already matched against
	// this request's TLS peer certificate or DPoP proof; empty for a bearer
	// token.
	CertificateThumbprint string
	JWKThumbprint         string
}

// PermissionScope is a credential's group binding: the group, the issuer
// whose group it is, and the group's persona.
type PermissionScope struct {
	GroupID         string
	AuthorityIssuer string
	Persona         iam.Persona
}

// IsUser reports whether the claims are a local user's.
func (c Claims) IsUser() bool { return c.Kind == iam.ActorUser && c.UserID != "" }

// IsResourceToken reports whether the claims are an RFC 9068 resource
// access token's (at+jwt): an authorization server's grant to a client for
// this resource server, never a sign-in of this deployment.
func (c Claims) IsResourceToken() bool { return isResourceType(c.JOSEType) }

// HasScope reports whether a resource access token was granted scope.
func (c Claims) HasScope(scope string) bool {
	for _, s := range c.Scopes {
		if s == scope {
			return true
		}
	}
	return false
}

// HasPermission reports whether the claims carry a permission covering perm.
func (c Claims) HasPermission(perm iam.Perm) bool {
	for _, p := range c.Permissions {
		if perm.Matches(ident.Perm(p)) {
			return true
		}
	}
	return false
}

// HasEntitlement reports whether the claims carry entitlement ent.
func (c Claims) HasEntitlement(ent string) bool {
	for _, e := range c.Entitlements {
		if strings.EqualFold(e, ent) {
			return true
		}
	}
	return false
}

// HasAMR reports whether the sign-in used authentication method m.
func (c Claims) HasAMR(m string) bool {
	for _, have := range c.AMR {
		if strings.EqualFold(strings.TrimSpace(have), strings.TrimSpace(m)) {
			return true
		}
	}
	return false
}

// Identity is the claims' provider-neutral identity (helpers/auth); ok is
// false when they name no subject under an issuer.
func (c Claims) Identity() (auth.Identity, bool) {
	i := auth.Identity{Issuer: c.Issuer, Email: c.Email, EmailVerified: c.EmailVerified, Username: c.Username, SessionID: c.SessionID}
	switch c.Kind {
	case iam.ActorUser:
		i.Kind, i.Subject = auth.KindUser, c.UserID
		if i.Subject == "" {
			i.Subject = c.Subject
		}
		if c.DeviceKeyID != "" {
			i.Kind, i.Subject = auth.KindDeviceKey, c.DeviceKeyID
		}
	case iam.ActorAPIKey:
		i.Kind, i.Subject = auth.KindAPIKey, c.APIKeyID
		if c.Group != nil {
			i.Issuer = c.Group.AuthorityIssuer
		}
	case iam.ActorRemoteApplication:
		i.Kind, i.Subject = auth.KindRemoteApplication, c.RemoteApplicationID
	case iam.ActorDelegated:
		i.Kind, i.Subject = auth.KindDelegated, c.DelegatedSubject
	case iam.ActorOAuthClient:
		// helpers/auth's machine identity: an application acting for itself.
		i.Kind, i.Subject = auth.KindRemoteApplication, c.ClientID
	default:
		return auth.Identity{}, false
	}
	if strings.TrimSpace(i.Subject) == "" || strings.TrimSpace(i.Issuer) == "" {
		return auth.Identity{}, false
	}
	return i, true
}

type claimsKey struct{}

// verified is what the middleware stores in a request context: the claims,
// the actor they act as, and, when a gate verified them, its authenticator
// and the request credential (Authorization and DPoP headers) it verified.
type verified struct {
	claims     Claims
	actor      iam.Actor
	by         Authenticator
	credential [2]string
}

// SetClaims stores cl in ctx for the handlers. The gates and
// AuthenticateRequest never trust claims stored this way: they verify the
// request themselves.
func SetClaims(ctx context.Context, cl Claims) context.Context {
	actor, _ := ActorFromClaims(cl)
	return context.WithValue(ctx, claimsKey{}, verified{claims: cl, actor: actor})
}

// setVerified stores the claims a verified r to carry.
func setVerified(r *http.Request, a Authenticator, cl Claims) *http.Request {
	actor, _ := ActorFromClaims(cl)
	return r.WithContext(context.WithValue(r.Context(), claimsKey{}, verified{claims: cl, actor: actor, by: a, credential: credential(r)}))
}

// verifiedBy is the claims a gate over a stored in ctx for r's credential:
// verifying r again would spend its sender proof twice. Only a pointer
// authenticator is recognized: comparing any other could panic.
func verifiedBy(ctx context.Context, r *http.Request, a Authenticator) (Claims, bool) {
	v, ok := ctx.Value(claimsKey{}).(verified)
	if !ok || v.by == nil || reflect.ValueOf(v.by).Kind() != reflect.Pointer || v.by != a || v.credential != credential(r) {
		return Claims{}, false
	}
	return v.claims, true
}

func credential(r *http.Request) [2]string {
	return [2]string{r.Header.Get("Authorization"), r.Header.Get("DPoP")}
}

// ClaimsFromContext is the claims the middleware stored in ctx.
func ClaimsFromContext(ctx context.Context) (Claims, bool) {
	v, ok := ctx.Value(claimsKey{}).(verified)
	return v.claims, ok
}

// CallerFromContext is the caller a gate over a verified and stored in ctx,
// as helpers/auth Auth.Caller reports it: a person (a user's token, a device
// key's included, by user id) or a Machine (an API key, a remote
// application). It is false without one, for claims SetClaims or a gate over
// another authenticator stored, and for any other credential (a delegation, a
// resource access token, another issuer's user).
func CallerFromContext(ctx context.Context, a Authenticator) (auth.Caller, bool) {
	v, ok := ctx.Value(claimsKey{}).(verified)
	if !ok || v.by == nil || reflect.ValueOf(v.by).Kind() != reflect.Pointer || v.by != a {
		return auth.Caller{}, false
	}
	cl := v.claims
	c := auth.Caller{Email: cl.Email, Username: cl.Username, EmailVerified: cl.EmailVerified}
	switch cl.Kind {
	case iam.ActorUser:
		id, err := uuid.Parse(cl.UserID)
		if err != nil || cl.TwoFAEnrollment || cl.IsResourceToken() {
			return auth.Caller{}, false
		}
		c.ID, c.Issuer, c.Credential = id.String(), cl.Issuer, string(auth.KindUser)
		if cl.DeviceKeyID != "" {
			c.Credential = string(auth.KindDeviceKey)
		}
	case iam.ActorAPIKey, iam.ActorRemoteApplication:
		i, ok := cl.Identity()
		if !ok {
			return auth.Caller{}, false
		}
		c.ID, c.Issuer, c.Credential, c.Machine = i.Subject, i.Issuer, string(i.Kind), true
	default:
		return auth.Caller{}, false
	}
	return c, true
}

// IdentityFromContext is the verified caller's provider-neutral identity.
func IdentityFromContext(ctx context.Context) (auth.Identity, bool) {
	cl, ok := ClaimsFromContext(ctx)
	if !ok {
		return auth.Identity{}, false
	}
	return cl.Identity()
}
