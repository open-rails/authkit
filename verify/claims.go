package verify

import (
	"cmp"
	"context"
	"encoding/json"
	"net/http"
	"reflect"
	"strings"
	"time"

	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/ident"
	"github.com/open-rails/helpers/auth"
)

// TokenKind is the class of credential verified Claims hold: which of their
// fields apply. It is not the subject's kind (Claims.Identity).
type TokenKind string

const (
	// TokenUser is a user's token: a native one (UserID), another issuer's
	// (Subject), or a resource access token for a user.
	TokenUser TokenKind = "user"
	// TokenAPIKey is one of this deployment's API keys (*authkit.Client).
	TokenAPIKey TokenKind = "api_key"
	// TokenOAuthClient is an OAuth client's own resource access token
	// (at+jwt) whose sub is its client_id. It carries no AuthKit authority.
	TokenOAuthClient TokenKind = "oauth_client"
)

// Claims is a verified credential: what the middleware stores in the request
// context. Kind says which fields apply.
type Claims struct {
	Kind TokenKind
	// JOSEType is the token's typ header ("access+jwt", "at+jwt"); empty
	// for an API key.
	JOSEType string
	// Issuer is the validated iss.
	Issuer string

	// UserID is a local user: set only for an issuer registered IsLocal.
	UserID string
	// Subject is another issuer's user, or a resource access token's sub
	// (its user, or its client acting for itself) whichever issuer minted it.
	// It is meaningful only with Issuer and never names a local user.
	Subject string
	// SessionID (sid) or DeviceKeyID names the sign-in a native token was
	// minted from, or for a local issuer's jwt-bearer resource token the
	// device key that signed its capability; the session check refuses the
	// token once it is revoked.
	SessionID   string
	DeviceKeyID string
	// APIKeyID is the key an API-key credential resolved to.
	APIKeyID string
	// Group binds an API key's authority to the group it was granted in;
	// nil otherwise.
	Group *PermissionScope

	// Permissions are the credential's permission strings: an API key's
	// stored grants, or a resource access token's grant for its audience (the
	// user's permissions within the resource server's ceiling at mint).
	// Native user tokens carry none; their authority is read live (Can).
	Permissions []string
	// Entitlements is the issuer's token-time entitlements snapshot.
	Entitlements []string
	// RootRole is the user's root-group role at mint ("root:admin"), for
	// display only: UI and content visibility without a database call. It is
	// stale up to the token lifetime and never authorizes anything; every
	// permission check reads the role live.
	RootRole string

	Email         string
	EmailVerified bool
	// Username is a native token's username, or a resource access token's
	// preferred_username.
	Username string
	// Name and UpdatedAt are a resource access token's OIDC name and
	// updated_at: the contact AuthKit puts in tokens for a resource with
	// ContactClaims, and when it last changed.
	Name      string
	UpdatedAt time.Time

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
	// AuthorizationDetails is a resource access token's RFC 9396 grant, the
	// raw JSON array; nil when it carries none.
	AuthorizationDetails json.RawMessage
	// Invoker is who acts for the user, from the RFC 8693 actor claim
	// (act.sub), the Identity's Invoker: the client after token exchange, the
	// workload the grant authorizer named after jwt-bearer.
	Invoker string
	// CustomClaims are a resource access token's claims named by an absolute
	// URI ("https://example.com/grant"), the issuer's own, each value raw JSON.
	CustomClaims map[string]json.RawMessage

	// CertificateThumbprint (cnf x5t#S256) or JWKThumbprint (cnf jkt) is a
	// resource token's sender binding, already matched against
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
func (c Claims) IsUser() bool { return c.Kind == TokenUser && c.UserID != "" }

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

// Identity is the claims' provider-neutral identity (helpers/auth): the
// Subject, native to Issuer, whose authority the credential uses; the
// Invoker who actually acts, the subject itself unless someone acts on its
// behalf; and the Credential that proved it, never the subject.
//
//   - A user's token is the user, by its session or device key.
//   - An OAuth client's client-credentials token is the client; its token
//     for a user is the user, invoked by the client.
//   - An API key is a credential of its group's account, an application
//     whose id is the group's, so rotating keys never changes the subject.
//
// ok is false when they name no subject under an issuer.
func (c Claims) Identity() (auth.Identity, bool) {
	i := auth.Identity{Issuer: c.Issuer, SubjectKind: auth.SubjectUser, Email: c.Email, EmailVerified: c.EmailVerified, Username: c.Username,
		Credential: auth.Credential{Kind: auth.CredentialAccessToken, ID: c.JTI}}
	authority := c.Issuer
	if c.Group != nil {
		authority = c.Group.AuthorityIssuer
	}
	var invoker *auth.Invoker
	switch c.Kind {
	case TokenUser:
		i.Subject = c.UserID
		if i.Subject == "" {
			i.Subject = c.Subject
		}
		switch {
		case c.IsResourceToken():
			if client := cmp.Or(c.Invoker, c.ClientID); client != "" {
				invoker = &auth.Invoker{Issuer: c.Issuer, ID: client}
			}
		case c.DeviceKeyID != "":
			i.Credential = auth.Credential{Kind: auth.CredentialDeviceKey, ID: c.DeviceKeyID}
		case c.SessionID != "":
			i.Credential = auth.Credential{Kind: auth.CredentialSession, ID: c.SessionID}
		}
	case TokenAPIKey:
		if c.Group != nil {
			i.Subject = c.Group.GroupID
		}
		i.Issuer, i.SubjectKind = authority, auth.SubjectApplication
		i.Credential = auth.Credential{Kind: auth.CredentialAPIKey, ID: c.APIKeyID}
	case TokenOAuthClient:
		i.Subject, i.SubjectKind = c.ClientID, auth.SubjectApplication
	default:
		return auth.Identity{}, false
	}
	if strings.TrimSpace(i.Subject) == "" || strings.TrimSpace(i.Issuer) == "" {
		return auth.Identity{}, false
	}
	i.Invoker = auth.Invoker{Issuer: i.Issuer, ID: i.Subject}
	if invoker != nil {
		if strings.TrimSpace(invoker.ID) == "" || strings.TrimSpace(invoker.Issuer) == "" {
			return auth.Identity{}, false
		}
		i.Invoker = *invoker
	}
	return i, true
}

type claimsKey struct{}

// verified is what the middleware stores in a request context: the claims,
// their identity, and, when a gate verified them, its authenticator and the
// request credential (Authorization and DPoP headers) it verified. Only a
// gate's identity carries AuthKit's credential state.
type verified struct {
	claims     Claims
	identity   auth.Identity
	by         Authenticator
	credential [2]string
}

// SetClaims stores cl in ctx for the handlers. Nothing trusts claims stored
// this way: the gates and AuthenticateRequest verify the request themselves,
// and their identity (IdentityFromContext) grants nothing.
func SetClaims(ctx context.Context, cl Claims) context.Context {
	id, _ := cl.Identity()
	return context.WithValue(ctx, claimsKey{}, verified{claims: cl, identity: id})
}

// setVerified stores the claims a verified r to carry.
func setVerified(r *http.Request, a Authenticator, cl Claims) *http.Request {
	id, ok := boundIdentity(cl)
	if !ok {
		id, _ = cl.Identity()
	}
	return r.WithContext(context.WithValue(r.Context(), claimsKey{}, verified{claims: cl, identity: id, by: a, credential: credential(r)}))
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

// VerifiedIdentity is the identity a gate over a verified and stored in ctx
// (IdentityFromContext), as helpers/auth Auth.Identity reports it. It is
// false without one, and for claims SetClaims or a gate over another
// authenticator stored: only a gate's own verification proves who called.
func VerifiedIdentity(ctx context.Context, a Authenticator) (auth.Identity, bool) {
	v, ok := ctx.Value(claimsKey{}).(verified)
	if !ok || v.by == nil || reflect.ValueOf(v.by).Kind() != reflect.Pointer || v.by != a || v.identity.Subject == "" {
		return auth.Identity{}, false
	}
	return v.identity, true
}
