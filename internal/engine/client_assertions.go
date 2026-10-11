package engine

// private_key_jwt client authentication (RFC 7523 §2.2, OIDC Core §9): a
// group client signs an assertion with a key its jwks_uri publishes, fetched
// through the SSRF-guarded client and cached like trusted issuers' keys.

import (
	"context"
	"strings"
	"sync"
	"time"

	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/authflow"
	"github.com/open-rails/authkit/internal/jose"
	"github.com/open-rails/authkit/internal/netguard"
	"github.com/open-rails/authkit/verify"
)

type clientAssertionVerifier struct {
	v          *verify.Verifier
	mu         sync.Mutex
	registered map[string]time.Time // client id -> its keys' version
}

func (s *Engine) clientAssertionVerifier() *clientAssertionVerifier {
	s.clientAssertionsOnce.Do(func() {
		s.clientAssertions = &clientAssertionVerifier{
			v:          verify.NewVerifier(verify.WithHTTPClient(netguard.Client(netguard.DefaultTimeout, s.cfg.Token.AllowPrivateNetworkJWKS))),
			registered: map[string]time.Time{},
		}
	})
	return s.clientAssertions
}

// AuthenticateClientAssertion checks a private_key_jwt client's assertion:
// signed by its keys, iss and sub its id, aud this issuer or its token
// endpoint, at most five minutes to live, its jti spent once.
func (s *Engine) AuthenticateClientAssertion(ctx context.Context, client authflow.OAuthClient, assertion string) error {
	invalid := &authflow.OAuthError{Code: authflow.OAuthInvalidClient, Description: "client authentication failed", Status: 401}
	if client.Group == nil || client.Group.AuthMethod != iam.OAuthClientPrivateKeyJWT || assertion == "" || len(assertion) > 16<<10 {
		return invalid
	}
	cv := s.clientAssertionVerifier()
	cv.mu.Lock()
	if at, ok := cv.registered[client.ID]; !ok || !at.Equal(client.Group.UpdatedAt) {
		audiences := []string{s.cfg.Token.Issuer}
		if endpoint := s.oauthTokenEndpoint(); endpoint != "" {
			audiences = append(audiences, endpoint)
		}
		if err := cv.v.AddIssuer(client.ID, audiences, verify.IssuerOptions{JWKSURI: client.Group.JWKSURI}); err != nil {
			cv.mu.Unlock()
			return invalid
		}
		cv.registered[client.ID] = client.Group.UpdatedAt
	}
	cv.mu.Unlock()
	claims, err := cv.v.VerifyClaims(ctx, assertion)
	if err != nil {
		return invalid
	}
	now := s.nowTime()
	exp, ok := jose.Time(claims, "exp")
	jti := jose.String(claims, "jti")
	switch {
	case jose.String(claims, "sub") != client.ID:
		return invalid
	case !ok || exp.After(now.Add(5*time.Minute+authflow.AssertionSkew)):
		return invalid
	case len(jti) < 16 || len(jti) > 128 || strings.ContainsAny(jti, " \t\r\n"):
		return invalid
	}
	fresh, err := s.replays.Claim(ctx, "client-assertion:"+client.ID+":"+jti, time.Until(exp)+authflow.AssertionSkew)
	if err != nil {
		return err
	}
	if !fresh {
		return invalid
	}
	return nil
}
