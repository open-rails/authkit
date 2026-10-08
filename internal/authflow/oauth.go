package authflow

import (
	"fmt"
	"net/http"
	"time"
)

// OAuthAuthorization is a validated authorization request waiting for its
// user: the authorize endpoint stores it, the SPA signs the user in and
// approves or declines it.
type OAuthAuthorization struct {
	ClientID      string    `json:"client_id"`
	RedirectURI   string    `json:"redirect_uri"`
	State         string    `json:"state,omitempty"`
	Nonce         string    `json:"nonce,omitempty"`
	Scopes        []string  `json:"scopes"`
	Resource      string    `json:"resource,omitempty"`
	CodeChallenge string    `json:"code_challenge"`
	Prompt        []string  `json:"prompt,omitempty"`
	MaxAge        *int64    `json:"max_age,omitempty"`
	LoginHint     string    `json:"login_hint,omitempty"`
	CreatedAt     time.Time `json:"created_at"`
	ExpiresAt     time.Time `json:"expires_at"`
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
}

// OAuthTokens is a token endpoint answer (RFC 6749 §5.1). Absent members
// are omitted, as the protocol expects.
type OAuthTokens struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int64  `json:"expires_in"`
	Scope        string `json:"scope,omitempty"`
	IDToken      string `json:"id_token,omitempty"`
	RefreshToken string `json:"refresh_token,omitempty"`
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
	OAuthRequestNotSupported     = "request_not_supported"
	OAuthRequestURINotSupported  = "request_uri_not_supported"
	OAuthInvalidToken            = "invalid_token"
	OAuthServerError             = "server_error"
	OAuthTemporarilyUnavailable  = "temporarily_unavailable"
)

// NewOAuthError builds an OAuthError.
func NewOAuthError(code, description string) *OAuthError {
	return &OAuthError{Code: code, Description: description}
}
