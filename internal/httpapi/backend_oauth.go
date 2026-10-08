package httpapi

import (
	"context"

	"github.com/open-rails/authkit/internal/authflow"
)

// oauthBackend is the authorization server's state and minting (#430).
type oauthBackend interface {
	BeginOAuthAuthorization(ctx context.Context, a authflow.OAuthAuthorization) (string, error)
	OAuthAuthorization(ctx context.Context, id string) (authflow.OAuthAuthorization, error)
	ApproveOAuthAuthorization(ctx context.Context, userID, sessionID, id string) (string, error)
	DeclineOAuthAuthorization(ctx context.Context, id, code string) (string, error)
	ExchangeOAuthCode(ctx context.Context, in authflow.OAuthCodeExchange) (authflow.OAuthTokens, error)
	OAuthUserInfo(ctx context.Context, accessToken string) (map[string]any, error)
	EndOAuthSession(ctx context.Context, in authflow.OAuthEndSession) (string, error)
}
