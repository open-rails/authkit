package httpapi

import (
	"context"

	"github.com/open-rails/authkit/internal/authflow"
	"github.com/open-rails/authkit/internal/errmodel"
	"github.com/open-rails/helpers/auth"
)

// oauthBackend is the authorization server's state and minting (#430, #432, #437).
type oauthBackend interface {
	BeginOAuthAuthorization(ctx context.Context, a authflow.OAuthAuthorization) (string, error)
	OAuthAuthorization(ctx context.Context, id string) (authflow.OAuthAuthorization, error)
	ApproveOAuthAuthorization(ctx context.Context, userID, sessionID, id string, consented bool) (string, error)
	OAuthClient(ctx context.Context, clientID string) (authflow.OAuthClient, bool, error)
	OAuthClientOrigin(ctx context.Context, origin string) (bool, error)
	AuthenticateClientAssertion(ctx context.Context, client authflow.OAuthClient, assertion string) error
	ScopeDescriptions(scopes []string) []errmodel.ScopeDescription
	GroupName(ctx context.Context, groupID string) *string
	WithdrawConsent(ctx context.Context, who auth.Identity, userID, clientID string) error
	DeclineOAuthAuthorization(ctx context.Context, id, code string) (string, error)
	ExchangeOAuthCode(ctx context.Context, in authflow.OAuthCodeExchange) (authflow.OAuthTokens, error)
	RefreshOAuthTokens(ctx context.Context, in authflow.OAuthRefresh) (authflow.OAuthTokens, error)
	ExchangeOAuthToken(ctx context.Context, in authflow.OAuthTokenExchange) (authflow.OAuthTokens, error)
	OAuthClientCredentials(ctx context.Context, in authflow.OAuthClientCredentials) (authflow.OAuthTokens, error)
	OAuthJWTBearer(ctx context.Context, in authflow.OAuthJWTBearer) (authflow.OAuthTokens, error)
	OAuthRemoteAssertion(ctx context.Context, in authflow.OAuthJWTBearer) (authflow.OAuthTokens, error)
	RevokeOAuthToken(ctx context.Context, clientID, token string) error
	OAuthUserInfo(ctx context.Context, accessToken, jkt string) (map[string]any, error)
	EndOAuthSession(ctx context.Context, in authflow.OAuthEndSession) (string, error)
}
