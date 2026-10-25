package critical_test

import (
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/open-rails/authkit"
	"github.com/open-rails/authkit/auth"
	"github.com/open-rails/authkit/authtest"
	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/verify"
)

func TestCriticalVerifiedCredentialExpiry(t *testing.T) {
	t.Run("AK-J13-C08_retained_verified_credentials_end_at_their_verified_deadline", func(t *testing.T) {
		const resource = "https://expiry-resource.example"
		f := newFixture(t, authtest.WithConfig(func(c *authkit.Config) {
			c.Resource = authkit.ResourceConfig{ID: resource}
			c.AuthorizationServer.Resources = []authkit.ResourceServerConfig{{ID: resource, Permissions: []string{"shop:*"}}}
			c.AuthorizationServer.Clients = []authkit.OAuthClientConfig{{ID: "expiry-client", RedirectURIs: []string{"https://client.example/callback"}, Resources: []string{resource}}}
		}))
		group, _, _ := f.ownedGroup(t)
		user := f.user(t)
		f.grant(t, group, user, f.reader)
		session := f.signIn(t, user)
		scope, err := f.auth.Scope(t.Context(), iam.GroupByID(group.ID))
		noError(t, err)
		zeroSkew, err := f.auth.NewVerifier([]string{authtest.Audience}, verify.WithSkew(0), verify.WithPublicURL(proofOrigin))
		noError(t, err)
		for _, sample := range []struct {
			name     string
			provider auth.Authenticator
			skew     time.Duration
			resource bool
			dpop     bool
		}{
			{"native_five_second_leeway", f.auth.Authenticator(), 5 * time.Second, false, false},
			{"host_zero_leeway", zeroSkew.Authenticator(), 0, false, false},
			{"resource_sixty_second_leeway", f.auth.Authenticator(), time.Minute, true, false},
			{"sender_proof_is_not_spent_again", zeroSkew.Authenticator(), 0, false, true},
		} {
			t.Run(sample.name, func(t *testing.T) {
				header, claims := jwtParts(t, session.AccessToken)
				deadline := time.Now().UTC().Truncate(time.Second).Add(4 * time.Second)
				claims["exp"] = deadline.Add(-sample.skew).Unix()
				claims["iat"], claims["auth_time"] = time.Now().Add(-2*time.Minute).Unix(), time.Now().Add(-2*time.Minute).Unix()
				delete(claims, "nbf")
				if sample.resource {
					header["typ"] = "at+jwt"
					claims["aud"], claims["client_id"] = []string{resource}, "expiry-client"
				}
				var sender *authtest.DPoPKey
				if sample.dpop {
					sender = authtest.NewDPoPKey(t)
					claims["cnf"] = map[string]any{"jkt": sender.Thumbprint()}
				}
				token := signJWT(t, f.deps.KeySource.ActiveSigner(), header, claims)
				request, err := http.NewRequestWithContext(t.Context(), http.MethodGet, proofOrigin+"/stream", nil)
				noError(t, err)
				request.Header.Set("Authorization", "Bearer "+token)
				if sender != nil {
					request.Header.Set("Authorization", "DPoP "+token)
					request.Header.Set("DPoP", sender.Proof(t, http.MethodGet, request.URL.String(), token, ""))
				}
				verified, err := sample.provider.Authenticate(request)
				noError(t, err)
				can := verified.(auth.PermissionChecker)
				direct := verified.(auth.DirectPermissionChecker)
				recent := verified.(auth.RecentSignInChecker)
				for range 2 {
					actor, err := f.auth.ResolveTenantActor(t.Context(), verified)
					noError(t, err)
					if actor.AccountID != user.ID || actor.TenantID != f.tenant {
						t.Fatalf("retained credential resolved wrong source account: %+v", actor)
					}
					allowed, err := can.Can(t.Context(), scope, f.read.String())
					noError(t, err)
					if !allowed {
						t.Fatal("valid retained credential lost its actual group permission")
					}
					allowed, err = direct.CanDirect(t.Context(), scope, f.read.String())
					noError(t, err)
					if !allowed {
						t.Fatal("valid retained credential lost its direct grant")
					}
					noError(t, recent.CheckRecentSignIn(t.Context()))
				}
				if sender != nil {
					if _, err := sample.provider.Authenticate(request); !errors.Is(err, auth.ErrUnauthenticated) {
						t.Fatal("positive replay control did not spend the original DPoP proof")
					}
				}
				if remaining := time.Until(deadline.Add(25 * time.Millisecond)); remaining > 0 {
					time.Sleep(remaining)
				}
				actor, err := f.auth.ResolveTenantActor(t.Context(), verified)
				if actor != (iam.TenantActor{}) || !errors.Is(err, auth.ErrUnauthenticated) || !errors.Is(err, auth.ErrExpired) {
					t.Errorf("source actor survived verified deadline: actor=%+v err=%v", actor, err)
				}
				for _, target := range []auth.Scope{scope, {}} {
					for name, check := range map[string]func() (bool, error){
						"Can":       func() (bool, error) { return can.Can(t.Context(), target, f.read.String()) },
						"CanDirect": func() (bool, error) { return direct.CanDirect(t.Context(), target, f.read.String()) },
					} {
						allowed, err := check()
						if allowed || !errors.Is(err, auth.ErrUnauthenticated) || !errors.Is(err, auth.ErrExpired) {
							t.Errorf("%s retained authority past verified deadline: allowed=%v err=%v", name, allowed, err)
						}
					}
				}
				if err := recent.CheckRecentSignIn(t.Context()); !errors.Is(err, auth.ErrUnauthenticated) || !errors.Is(err, auth.ErrExpired) {
					t.Errorf("recent-sign-in check accepted expired credential: %v", err)
				}
			})
		}
	})
}
