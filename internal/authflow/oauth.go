package authflow

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// OAuthAuthorization is a validated authorization request waiting for its
// user: the authorize endpoint stores it, the SPA signs the user in and
// approves or declines it.
type OAuthAuthorization struct {
	ClientID      string   `json:"client_id"`
	RedirectURI   string   `json:"redirect_uri"`
	State         string   `json:"state,omitempty"`
	Nonce         string   `json:"nonce,omitempty"`
	Scopes        []string `json:"scopes"`
	Resource      string   `json:"resource,omitempty"`
	CodeChallenge string   `json:"code_challenge"`
	Prompt        []string `json:"prompt,omitempty"`
	MaxAge        *int64   `json:"max_age,omitempty"`
	LoginHint     string   `json:"login_hint,omitempty"`
	// DPoPJKT binds the code to a DPoP key (RFC 9449 §10): its redemption
	// must prove that key.
	DPoPJKT   string    `json:"dpop_jkt,omitempty"`
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at"`
}

// OAuthGrantDecision is the host authorizer's checked decision on a
// jwt-bearer grant: the operations, a lifetime cap, extra access-token
// claims and the invoker.
type OAuthGrantDecision struct {
	AuthorizationDetails json.RawMessage
	MaxLifetime          time.Duration
	Claims               map[string]any
	Invoker              string
}

// OAuthGrant is what an authorization code stands for: the approved request
// and the sign-in that approved it.
type OAuthGrant struct {
	ClientID      string   `json:"client_id"`
	RedirectURI   string   `json:"redirect_uri"`
	CodeChallenge string   `json:"code_challenge"`
	Nonce         string   `json:"nonce,omitempty"`
	Scopes        []string `json:"scopes"`
	Resource      string   `json:"resource,omitempty"`
	UserID        string   `json:"user_id"`
	SessionID     string   `json:"session_id"`
	AuthTime      int64    `json:"auth_time"`
	AMR           []string `json:"amr"`
	ACR           string   `json:"acr"`
	DPoPJKT       string   `json:"dpop_jkt,omitempty"`
	// ConsentAt is when the user's consent to a third-party client was
	// granted: the code and its tokens end with that consent.
	ConsentAt *time.Time `json:"consent_at,omitempty"`
}

// OAuthCodeExchange is an authorization_code token request from an
// authenticated (or public) client.
type OAuthCodeExchange struct {
	ClientID     string
	Code         string
	RedirectURI  string
	CodeVerifier string
	// Resource is the request's resource parameter; "" takes the authorized
	// one.
	Resource string
	// JKT is the thumbprint of the request's DPoP proof key; "" without
	// DPoP. The tokens are bound to it.
	JKT string
}

// OAuthRefresh is a refresh_token token request.
type OAuthRefresh struct {
	ClientID     string
	RefreshToken string
	// Scopes narrows the family's scopes; nil keeps them.
	Scopes   []string
	Resource string
	JKT      string
}

// OAuthTokenExchange is an RFC 8693 token exchange request: the user's
// AuthKit access token for an access token to a resource.
type OAuthTokenExchange struct {
	ClientID           string
	SubjectToken       string
	SubjectTokenType   string
	RequestedTokenType string
	Resource           string
	Scopes             []string
	JKT                string
}

// OAuthClientCredentials is a client_credentials token request.
type OAuthClientCredentials struct {
	ClientID string
	Resource string
	Scopes   []string
	JKT      string
}

// RFC 8693 token type identifiers.
const (
	TokenTypeAccessToken = "urn:ietf:params:oauth:token-type:access_token"
	TokenTypeJWT         = "urn:ietf:params:oauth:token-type:jwt"
)

// OAuthTokens is a token endpoint answer (RFC 6749 §5.1). Absent members
// are omitted, as the protocol expects.
type OAuthTokens struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int64  `json:"expires_in"`
	Scope        string `json:"scope,omitempty"`
	IDToken      string `json:"id_token,omitempty"`
	RefreshToken string `json:"refresh_token,omitempty"`
	// IssuedTokenType answers a token exchange (RFC 8693 §2.2.1).
	IssuedTokenType string `json:"issued_token_type,omitempty"`
	// AuthorizationDetails is what the access token was granted (RFC 9396
	// §7.1).
	AuthorizationDetails json.RawMessage `json:"authorization_details,omitempty"`
}

// OAuthEndSession is an RP-initiated logout request.
type OAuthEndSession struct {
	IDTokenHint           string
	ClientID              string
	PostLogoutRedirectURI string
	State                 string
}

// OAuthError is an OAuth 2.0 protocol error (RFC 6749 §4.1.2.1, §5.2): the
// error code a client branches on and a human-readable description.
type OAuthError struct {
	Code        string
	Description string
	// Status is the HTTP status for a direct (non-redirect) answer; 0 means
	// 400.
	Status int
	// Reason is a stable machine-readable cause beside Code ("reason"),
	// which the jwt-bearer grant sets.
	Reason string
}

func (e *OAuthError) Error() string { return fmt.Sprintf("oauth: %s: %s", e.Code, e.Description) }

// HTTPStatus is the status a direct answer carries.
func (e *OAuthError) HTTPStatus() int {
	if e.Status == 0 {
		return http.StatusBadRequest
	}
	return e.Status
}

// OAuth error codes AuthKit answers.
const (
	OAuthInvalidRequest          = "invalid_request"
	OAuthInvalidClient           = "invalid_client"
	OAuthInvalidGrant            = "invalid_grant"
	OAuthUnauthorizedClient      = "unauthorized_client"
	OAuthUnsupportedGrantType    = "unsupported_grant_type"
	OAuthUnsupportedResponseType = "unsupported_response_type"
	OAuthInvalidScope            = "invalid_scope"
	OAuthInvalidTarget           = "invalid_target"
	OAuthAccessDenied            = "access_denied"
	OAuthLoginRequired           = "login_required"
	OAuthInteractionRequired     = "interaction_required"
	OAuthConsentRequired         = "consent_required"
	OAuthRequestNotSupported     = "request_not_supported"
	OAuthRequestURINotSupported  = "request_uri_not_supported"
	OAuthInvalidToken            = "invalid_token"
	OAuthInvalidDPoPProof        = "invalid_dpop_proof"
	OAuthUseDPoPNonce            = "use_dpop_nonce"
	OAuthUnsupportedTokenType    = "unsupported_token_type"
	OAuthServerError             = "server_error"
	OAuthTemporarilyUnavailable  = "temporarily_unavailable"
	// OAuthInvalidAuthorizationDetails is RFC 9396 §5's.
	OAuthInvalidAuthorizationDetails = "invalid_authorization_details"
)

// NewOAuthError builds an OAuthError.
func NewOAuthError(code, description string) *OAuthError {
	return &OAuthError{Code: code, Description: description}
}
