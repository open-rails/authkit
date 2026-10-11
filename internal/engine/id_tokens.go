package engine

import (
	"context"
	"errors"

	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/authflow"
	"github.com/open-rails/authkit/internal/jose"
)

// VerifyIDToken verifies an ID token this deployment's authorization server
// issued, in process: its signature, issuer, single audience (its azp),
// lifetime, a client still registered and enabled, and a sign-in that still
// stands (its user neither deleted nor banned). Anything else is
// iam.ErrInvalidIDToken; a store failure stays an error.
func (s *Engine) VerifyIDToken(ctx context.Context, raw string) (iam.IDToken, error) {
	claims, err := s.verifyOwnToken(raw, idTokenType)
	if err != nil {
		return iam.IDToken{}, iam.ErrInvalidIDToken
	}
	now := s.nowTime()
	azp, audiences := jose.String(claims, "azp"), jose.Audiences(claims)
	exp, okExp := jose.Time(claims, "exp")
	iat, okIat := jose.Time(claims, "iat")
	authTime, _ := jose.Time(claims, "auth_time")
	switch {
	case azp == "" || len(audiences) != 1 || audiences[0] != azp:
		return iam.IDToken{}, iam.ErrInvalidIDToken
	case !okExp || !now.Before(exp.Add(authflow.AssertionSkew)):
		return iam.IDToken{}, iam.ErrInvalidIDToken
	case !okIat || iat.After(now.Add(authflow.AssertionSkew)):
		return iam.IDToken{}, iam.ErrInvalidIDToken
	}
	client, ok, err := s.OAuthClient(ctx, azp)
	if err != nil {
		return iam.IDToken{}, err
	}
	if !ok {
		return iam.IDToken{}, iam.ErrInvalidIDToken
	}
	userID, sessionID := jose.String(claims, "sub"), jose.String(claims, "sid")
	if err := s.oauthSignInStands(ctx, userID, sessionID, "the sign-in has ended"); err != nil {
		if refused := (*authflow.OAuthError)(nil); errors.As(err, &refused) {
			return iam.IDToken{}, iam.ErrInvalidIDToken
		}
		return iam.IDToken{}, err
	}
	out := iam.IDToken{
		Subject: userID, ClientID: azp, SessionID: sessionID, Nonce: jose.String(claims, "nonce"),
		AuthTime: authTime.UTC(), AMR: jose.Strings(claims, "amr"), ACR: jose.String(claims, "acr"),
		IssuedAt: iat.UTC(), ExpiresAt: exp.UTC(),
	}
	if client.Group != nil {
		out.GroupID = client.Group.GroupID
	}
	return out, nil
}
