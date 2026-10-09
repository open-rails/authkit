package httpapi

import (
	"context"

	"github.com/open-rails/authkit/internal/authflow"
)

// oauthBackend is the authorization server's state and minting (#430, #432).
type oauthBackend interface {
	BeginOAuthAuthorization(ctx context.Context, a authflow.OAuthAuthorization) (string, error)
	OAuthAuthorization(ctx context.Context, id string) (authflow.OAuthAuthorization, error)
	ApproveOAuthAuthorization(ctx context.Context, userID, sessionID, id string) (string, error)
	DeclineOAuthAuthorization(ctx context.Context, id, code string) (string, error)
	ExchangeOAuthCode(ctx context.Context, in authflow.OAuthCodeExchange) (authflow.OAuthTokens, error)
	RefreshOAuthTokens(ctx context.Context, in authflow.OAuthRefresh) (authflow.OAuthTokens, error)
	ExchangeOAuthToken(ctx context.Context, in authflow.OAuthTokenExchange) (authflow.OAuthTokens, error)
	OAuthClientCredentials(ctx context.Context, in authflow.OAuthClientCredentials) (authflow.OAuthTokens, error)
	RevokeOAuthToken(ctx context.Context, clientID, token string) error
	OAuthUserInfo(ctx context.Context, accessToken, jkt string) (map[string]any, error)
	EndOAuthSession(ctx context.Context, in authflow.OAuthEndSession) (string, error)
}
