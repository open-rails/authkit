package iam

import (
	"time"

	"github.com/open-rails/authkit/internal/errmodel"
)

// MaxGroupOAuthClients is the most OAuth clients one group registers.
const MaxGroupOAuthClients = 10

// OAuthClientAuthMethod is how a group's OAuth client authenticates at the
// token endpoint (RFC 7591 token_endpoint_auth_method).
type OAuthClientAuthMethod string

const (
	// OAuthClientPrivateKeyJWT signs an RFC 7523 client assertion with a
	// key its JWKSURI publishes.
	OAuthClientPrivateKeyJWT OAuthClientAuthMethod = "private_key_jwt"
	// OAuthClientSecretBasic sends the secret AuthKit issued it, by HTTP
	// Basic authentication.
	OAuthClientSecretBasic OAuthClientAuthMethod = "client_secret_basic"
	// OAuthClientNone is a public client, such as a single-page app: no
	// secret, PKCE and DPoP only.
	OAuthClientNone OAuthClientAuthMethod = "none"
)

// OAuthClient is an OAuth client a group registered at run time, by RFC
// 7591's metadata. It signs the group's users in at this deployment, each
// consenting to the scopes it asks for; its tokens act only in its group.
type OAuthClient struct {
	ClientID string `json:"client_id"`
	GroupID  string `json:"group_id"`
	// ClientName, LogoURI, ClientURI, PolicyURI and TOSURI are shown on the
	// consent screen, beside the group's own name.
	ClientName              string                `json:"client_name"`
	LogoURI                 *string               `json:"logo_uri"`
	ClientURI               *string               `json:"client_uri"`
	PolicyURI               *string               `json:"policy_uri"`
	TOSURI                  *string               `json:"tos_uri"`
	RedirectURIs            []string              `json:"redirect_uris"`
	PostLogoutRedirectURIs  []string              `json:"post_logout_redirect_uris"`
	TokenEndpointAuthMethod OAuthClientAuthMethod `json:"token_endpoint_auth_method"`
	// JWKSURI publishes a private_key_jwt client's keys.
	JWKSURI *string `json:"jwks_uri"`
	// Scope is the space-separated scopes the client may request: openid,
	// email, phone, profile and the deployment's group-client scopes.
	Scope string `json:"scope"`
	// BackchannelLogoutURI receives an OIDC Back-Channel Logout token when a
	// user withdraws consent.
	BackchannelLogoutURI *string    `json:"backchannel_logout_uri"`
	Disabled             bool       `json:"disabled"`
	CreatedAt            time.Time  `json:"created_at"`
	UpdatedAt            time.Time  `json:"updated_at"`
	DisabledAt           *time.Time `json:"disabled_at"`
}

// NewOAuthClient registers a group's OAuth client.
type NewOAuthClient struct {
	ClientName              string                `json:"client_name"`
	LogoURI                 string                `json:"logo_uri"`
	ClientURI               string                `json:"client_uri"`
	PolicyURI               string                `json:"policy_uri"`
	TOSURI                  string                `json:"tos_uri"`
	RedirectURIs            []string              `json:"redirect_uris"`
	PostLogoutRedirectURIs  []string              `json:"post_logout_redirect_uris"`
	TokenEndpointAuthMethod OAuthClientAuthMethod `json:"token_endpoint_auth_method"`
	JWKSURI                 string                `json:"jwks_uri"`
	Scope                   string                `json:"scope"`
	BackchannelLogoutURI    string                `json:"backchannel_logout_uri"`
}

// OAuthClientUpdate changes a group's OAuth client; nil fields stay, and ""
// clears an optional URI. The authentication method never changes: register
// another client.
type OAuthClientUpdate struct {
	ClientName             *string   `json:"client_name"`
	LogoURI                *string   `json:"logo_uri"`
	ClientURI              *string   `json:"client_uri"`
	PolicyURI              *string   `json:"policy_uri"`
	TOSURI                 *string   `json:"tos_uri"`
	RedirectURIs           *[]string `json:"redirect_uris"`
	PostLogoutRedirectURIs *[]string `json:"post_logout_redirect_uris"`
	JWKSURI                *string   `json:"jwks_uri"`
	Scope                  *string   `json:"scope"`
	BackchannelLogoutURI   *string   `json:"backchannel_logout_uri"`
	// Disabled refuses the client's sign-ins, and every token it holds at
	// its next use; false enables it again.
	Disabled *bool `json:"disabled"`
}

// OAuthClientCreated is a registered client and, for client_secret_basic,
// its secret, shown this once.
type OAuthClientCreated struct {
	OAuthClient
	ClientSecret *string `json:"client_secret"`
}

// OAuthConsent is a user's consent to a group's OAuth client: the scopes it
// may ask without asking again.
type OAuthConsent struct {
	ClientID   string `json:"client_id"`
	ClientName string `json:"client_name"`
	GroupID    string `json:"group_id"`
	// GroupName is the group's name as the host gives it (Deps.GroupName).
	GroupName *string   `json:"group_name"`
	LogoURI   *string   `json:"logo_uri"`
	ClientURI *string   `json:"client_uri"`
	Scopes    []string  `json:"scopes"`
	GrantedAt time.Time `json:"granted_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

var (
	// ErrOAuthClientNotFound: no such client in the group.
	ErrOAuthClientNotFound Error = errmodel.E(errmodel.CodeOAuthClientNotFound)
	// ErrOAuthClientLimitReached: the group has MaxGroupOAuthClients.
	ErrOAuthClientLimitReached Error = errmodel.E(errmodel.CodeOAuthClientLimitReached)
	// ErrInvalidOAuthClient: the metadata breaks a rule; the message says
	// which.
	ErrInvalidOAuthClient Error = errmodel.E(errmodel.CodeInvalidOAuthClient)
	// ErrConsentRequired: the user has not consented to every scope the
	// client asks for; metadata.scopes names the new ones.
	ErrConsentRequired Error = errmodel.E(errmodel.CodeConsentRequired)
	// ErrOAuthConsentNotFound: the user holds no consent to that client.
	ErrOAuthConsentNotFound Error = errmodel.E(errmodel.CodeOAuthConsentNotFound)
	// ErrConsentRevocationRefused matches every RefuseConsentRevocation
	// error.
	ErrConsentRevocationRefused Error = errmodel.E(errmodel.CodeConsentRevocationRefused)
	// ErrInvalidIDToken: not an ID token this deployment's authorization
	// server issued, expired, or one whose client or sign-in has ended.
	ErrInvalidIDToken Error = errmodel.E(errmodel.CodeInvalidIDToken)
)

// RefuseConsentRevocation is what Deps.ConsentRevocationCheck returns to
// refuse a user's withdrawal of consent: consent_revocation_refused (409),
// with reason, a stable code the host's interface explains, as
// metadata.reason.
func RefuseConsentRevocation(reason string) error {
	return errmodel.E(errmodel.CodeConsentRevocationRefused, errmodel.WithDetails(errmodel.Refusal{Reason: reason}))
}

// IDToken is a verified ID token of this deployment's authorization server
// (Client.VerifyIDToken): who signed in, to which client, and how.
type IDToken struct {
	// Subject is the user's id.
	Subject string
	// ClientID is the client it was issued to (its aud and azp); GroupID
	// the group that owns it, "" for a client of Config.AuthorizationServer.
	ClientID  string
	GroupID   string
	SessionID string
	Nonce     string
	AuthTime  time.Time
	AMR       []string
	ACR       string
	IssuedAt  time.Time
	ExpiresAt time.Time
}
