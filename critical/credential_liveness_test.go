package critical_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/open-rails/authkit"
	"github.com/open-rails/authkit/auth"
	"github.com/open-rails/authkit/authtest"
	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/keys"
	"github.com/open-rails/authkit/verify"
)

type liveForwardingVerified struct{ auth.Verified }

func (v liveForwardingVerified) CheckCredential(ctx context.Context) error {
	return v.Verified.(auth.CredentialChecker).CheckCredential(ctx)
}

func liveChecker(t *testing.T, verified auth.Verified) auth.CredentialChecker {
	t.Helper()
	checker, ok := verified.(auth.CredentialChecker)
	if !ok {
		t.Fatal("verified user credential lacks the documented live-check capability")
	}
	return checker
}

func liveProofRequest(t *testing.T, provider auth.Authenticator, token string, sender *authtest.DPoPKey) (auth.Verified, *http.Request) {
	t.Helper()
	r, err := http.NewRequestWithContext(t.Context(), http.MethodGet, proofOrigin+"/customer-proof", nil)
	noError(t, err)
	r.Header.Set("Authorization", "Bearer "+token)
	if sender != nil {
		sender.Authorize(t, r, token, "")
	}
	v, err := provider.Authenticate(r)
	var challenge *auth.Challenge
	if sender != nil && errors.As(err, &challenge) && challenge.Header.Get("DPoP-Nonce") != "" {
		// The server's nonce challenge precedes successful authentication.
		sender.Authorize(t, r, token, challenge.Header.Get("DPoP-Nonce"))
		v, err = provider.Authenticate(r)
	}
	noError(t, err)
	return v, r
}

func requireRevokedCredential(t *testing.T, checker auth.CredentialChecker) {
	t.Helper()
	if err := checker.CheckCredential(t.Context()); !errors.Is(err, auth.ErrUnauthenticated) || !errors.Is(err, auth.ErrRevoked) {
		t.Fatalf("retained credential stayed usable after authority ended: %v", err)
	}
}

// Block a real authority query, not an internal authorization result.
func credentialExpiresAfterDatabaseWait(t *testing.T, f *fixture, checker auth.CredentialChecker, deadline time.Time) {
	t.Helper()
	tx, err := f.pool.Begin(t.Context())
	noError(t, err)
	defer tx.Rollback(context.Background())
	_, err = tx.Exec(t.Context(), "LOCK TABLE "+pgx.Identifier{f.schema, "users"}.Sanitize()+" IN ACCESS EXCLUSIVE MODE")
	noError(t, err)
	short, cancel := context.WithTimeout(t.Context(), 100*time.Millisecond)
	err = checker.CheckCredential(short)
	cancel()
	if !errors.Is(err, auth.ErrUnavailable) || errors.Is(err, auth.ErrRevoked) {
		t.Fatalf("unavailable authority was mislabeled as revoked: %v", err)
	}
	finished := make(chan error, 1)
	go func() { finished <- checker.CheckCredential(t.Context()) }()
	waitEnd := time.Now().Add(2 * time.Second)
	for {
		select {
		case err := <-finished:
			t.Fatalf("credential check ended before its live query reached the owned lock: %v", err)
		default:
		}
		var blocked bool
		err = f.pool.QueryRow(t.Context(), `SELECT EXISTS(SELECT 1 FROM pg_locks WHERE relation=$1::regclass AND NOT granted)`, pgx.Identifier{f.schema, "users"}.Sanitize()).Scan(&blocked)
		noError(t, err)
		if blocked {
			break
		}
		if time.Now().After(waitEnd) {
			t.Fatal("credential check never reached the actual database lock")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if remaining := time.Until(deadline.Add(30 * time.Millisecond)); remaining > 0 {
		time.Sleep(remaining)
	}
	noError(t, tx.Rollback(t.Context()))
	if err := <-finished; !errors.Is(err, auth.ErrExpired) || !errors.Is(err, auth.ErrUnauthenticated) {
		t.Fatalf("credential survived expiry while its live read waited: %v", err)
	}
}

func TestCriticalCredentialLiveness(t *testing.T) {
	t.Run("AK-J13-C09_live_user_proof_checks_do_not_reauthenticate_or_grant_permissions", func(t *testing.T) {
		t.Run("native_revocation_and_expiry_during_database_wait", func(t *testing.T) {
			const waitingResource = "https://waiting-proof.example"
			f := newFixture(t, authtest.WithConfig(func(c *authkit.Config) {
				c.Resource = authkit.ResourceConfig{ID: waitingResource}
				c.AuthorizationServer.Resources = []authkit.ResourceServerConfig{{ID: waitingResource}}
				c.AuthorizationServer.Clients = []authkit.OAuthClientConfig{{ID: "waiting-client", RedirectURIs: []string{"https://client.example/callback"}, Resources: []string{waitingResource}}}
			}))
			u := f.user(t)
			session := f.signIn(t, u)
			stale := authtest.StaleSession(t, f.auth, session.AccessToken)
			v, _ := liveProofRequest(t, f.auth.Authenticator(), stale, nil)
			checker := liveChecker(t, liveForwardingVerified{v})
			noError(t, checker.CheckCredential(t.Context()))
			if err := v.(auth.RecentSignInChecker).CheckRecentSignIn(t.Context()); !errors.Is(err, auth.ErrStepUpRequired) {
				t.Fatalf("valid older sign-in did not exercise the no-step-up contract: %v", err)
			}
			claims, err := f.auth.Verify(t.Context(), stale)
			noError(t, err)
			noError(t, f.auth.CheckCredential(t.Context(), claims))
			group, _, owner := f.ownedGroup(t)
			key, err := f.auth.CreateAPIKey(t.Context(), owner, iam.GroupByID(group.ID), iam.NewAPIKey{Name: "unsupported live proof", Role: f.reader})
			noError(t, err)
			keyVerified, _ := liveProofRequest(t, f.auth.Authenticator(), key.Secret, nil)
			if err := liveChecker(t, keyVerified).CheckCredential(t.Context()); !errors.Is(err, auth.ErrForbidden) {
				t.Fatalf("API key acquired unsupported user-proof liveness: %v", err)
			}
			pat, err := f.auth.CreatePersonalAccessToken(t.Context(), owner, iam.NewPersonalAccessToken{Name: "unsupported personal proof", GroupID: group.ID, Permissions: []iam.Perm{f.read}})
			noError(t, err)
			patVerified, _ := liveProofRequest(t, f.auth.Authenticator(), pat.Secret, nil)
			if err := liveChecker(t, patVerified).CheckCredential(t.Context()); !errors.Is(err, auth.ErrForbidden) {
				t.Fatalf("personal token acquired unsupported user-proof liveness: %v", err)
			}
			// The request is already authenticated and waits before consuming
			// its proof; account revocation must stop the resumed operation.
			resume := make(chan struct{})
			finished := make(chan error, 1)
			go func() { <-resume; finished <- checker.CheckCredential(t.Context()) }()
			_, err = f.auth.RevokeAccountSessions(t.Context(), iam.UserIdentity(u.ID), u.ID)
			noError(t, err)
			close(resume)
			if err := <-finished; !errors.Is(err, auth.ErrRevoked) {
				t.Fatalf("request survived revocation while waiting: %v", err)
			}

			fresh := f.signIn(t, u)
			zero, err := f.auth.NewVerifier([]string{authtest.Audience}, verify.WithSkew(0))
			noError(t, err)
			for _, profile := range []struct {
				name     string
				provider auth.Authenticator
				skew     time.Duration
				resource bool
			}{
				{"native", zero.Authenticator(), 0, false},
				{"resource", f.auth.Authenticator(), time.Minute, true},
			} {
				t.Run(profile.name, func(t *testing.T) {
					header, body := jwtParts(t, fresh.AccessToken)
					deadline := time.Now().UTC().Truncate(time.Second).Add(4 * time.Second)
					body["exp"] = deadline.Add(-profile.skew).Unix()
					body["iat"], body["auth_time"] = time.Now().Add(-2*time.Minute).Unix(), time.Now().Add(-2*time.Minute).Unix()
					delete(body, "nbf")
					if profile.resource {
						header["typ"] = "at+jwt"
						body["aud"], body["client_id"] = waitingResource, "waiting-client"
					}
					verified, _ := liveProofRequest(t, profile.provider, signJWT(t, f.deps.KeySource.ActiveSigner(), header, body), nil)
					credentialExpiresAfterDatabaseWait(t, f, liveChecker(t, verified), deadline)
				})
			}
		})

		t.Run("asserted_and_sender_bound_resource_registration_is_live", func(t *testing.T) {
			const resource = "https://customer-proof.example"
			f := newFixture(t, authtest.WithConfig(func(c *authkit.Config) {
				c.Resource = authkit.ResourceConfig{ID: resource, PublicURL: proofOrigin, Scopes: map[string][]string{"customer:self": {}}}
			}))
			group, _, _ := f.ownedGroup(t)
			_, private, err := ed25519.GenerateKey(rand.Reader)
			noError(t, err)
			signer, err := keys.SignerFromKey("merchant-proof", private)
			noError(t, err)
			jwk := keys.PublicJWK(signer.Public(), signer.KID(), signer.Algorithm())
			registration := iam.RemoteApplication{Issuer: "https://merchant-" + uuid.NewString() + ".example", Enabled: true, Mode: iam.RemoteApplicationModeStatic, PublicKeys: []iam.RemoteApplicationKey{{KID: signer.KID(), JWK: &jwk}}}
			app, err := f.auth.UpsertRemoteApplication(t.Context(), iam.SystemIdentity(), iam.GroupByID(group.ID), registration)
			noError(t, err)
			customer := uuid.NewString()
			now := time.Now()
			assertion := signJWT(t, signer, map[string]any{"alg": signer.Algorithm(), "kid": signer.KID(), "typ": "JWT"}, map[string]any{"iss": app.Issuer, "sub": customer, "aud": f.cfg.Token.Issuer + iam.OAuthTokenPath, "iat": now.Unix(), "exp": now.Add(time.Minute).Unix(), "jti": uuid.NewString()})
			form := url.Values{"grant_type": {"urn:ietf:params:oauth:grant-type:jwt-bearer"}, "assertion": {assertion}, "scope": {"customer:self"}}
			response, err := f.server.Client().PostForm(f.server.URL+iam.OAuthTokenPath, form)
			noError(t, err)
			raw, err := io.ReadAll(response.Body)
			noError(t, err)
			response.Body.Close()
			if response.StatusCode != http.StatusOK {
				t.Fatalf("actual merchant assertion exchange: status=%d body=%s", response.StatusCode, raw)
			}
			var token struct {
				AccessToken string `json:"access_token"`
			}
			noError(t, json.Unmarshal(raw, &token))
			asserted, _ := liveProofRequest(t, f.auth.Authenticator(), token.AccessToken, nil)
			if !asserted.(auth.Asserted).Asserted() || asserted.Identity().Issuer != app.Issuer || asserted.Identity().Subject != customer {
				t.Fatal("real assertion exchange lost the merchant's own customer namespace")
			}
			noError(t, liveChecker(t, asserted).CheckCredential(t.Context()))
			if err := asserted.(auth.RecentSignInChecker).CheckRecentSignIn(t.Context()); err == nil {
				t.Fatal("merchant assertion unexpectedly manufactured a recent sign-in")
			}
			sender := authtest.NewDPoPKey(t)
			foreign := signJWT(t, signer, map[string]any{"alg": signer.Algorithm(), "kid": signer.KID(), "typ": "at+jwt"}, map[string]any{"iss": app.Issuer, "sub": customer, "aud": resource, "client_id": "merchant-ui", "scope": "customer:self", "iat": now.Unix(), "exp": now.Add(10 * time.Minute).Unix(), "jti": uuid.NewString(), "cnf": map[string]any{"jkt": sender.Thumbprint()}})
			verified, request := liveProofRequest(t, f.auth.Authenticator(), foreign, sender)
			for range 2 {
				noError(t, liveChecker(t, verified).CheckCredential(t.Context()))
			}
			if _, err := f.auth.Authenticator().Authenticate(request); !errors.Is(err, auth.ErrUnauthenticated) {
				t.Fatalf("resource replay control did not consume the original sender proof: %v", err)
			}
			if _, native := iam.StateOf(verified.Identity()); native {
				t.Fatal("resource liveness promoted remote identity to native permission authority")
			}
			app.Enabled = false
			_, err = f.auth.UpsertRemoteApplication(t.Context(), iam.SystemIdentity(), iam.GroupByID(group.ID), app)
			noError(t, err)
			requireRevokedCredential(t, liveChecker(t, asserted))
			requireRevokedCredential(t, liveChecker(t, verified))
			app.Enabled = true
			_, err = f.auth.UpsertRemoteApplication(t.Context(), iam.SystemIdentity(), iam.GroupByID(group.ID), app)
			noError(t, err)
			noError(t, liveChecker(t, asserted).CheckCredential(t.Context()))
			noError(t, f.auth.DeleteRemoteApplication(t.Context(), iam.SystemIdentity(), iam.GroupByID(group.ID), app.ID))
			other, _, _ := f.ownedGroup(t)
			_, err = f.auth.UpsertRemoteApplication(t.Context(), iam.SystemIdentity(), iam.GroupByID(other.ID), registration)
			noError(t, err)
			requireRevokedCredential(t, liveChecker(t, asserted))
			requireRevokedCredential(t, liveChecker(t, verified))
			fresh, _ := liveProofRequest(t, f.auth.Authenticator(), token.AccessToken, nil)
			if fresh.(auth.Bound).BoundScope().ID != other.ID {
				t.Fatal("fresh control did not resolve the newly registered application")
			}
			noError(t, f.auth.DeleteGroup(t.Context(), iam.GroupByID(other.ID)))
			requireRevokedCredential(t, liveChecker(t, fresh))
		})

		t.Run("registered_client_and_native_bound_group_do_not_outlive_deletion", func(t *testing.T) {
			const resource = "https://registered-customer.example"
			var persona iam.Persona
			f := newFixture(t, authtest.WithConfig(func(c *authkit.Config) {
				persona = c.Roles.Persona("proofclient", authkit.OAuthClients).Persona
				c.Resource = authkit.ResourceConfig{ID: resource, Scopes: map[string][]string{"customer:self": {}}}
				c.AuthorizationServer.Resources = []authkit.ResourceServerConfig{{ID: resource, Scopes: []string{"customer:self"}}}
				c.AuthorizationServer.GroupClients.Scopes = []authkit.GroupClientScope{{Name: "customer:self", Resource: resource, Description: "Read the customer's own records"}}
			}))
			u := f.user(t)
			session := f.signIn(t, u)
			owner := iam.UserSubject(u.ID)
			group, err := f.auth.CreateGroup(t.Context(), iam.NewGroup{Persona: persona, Owner: &owner})
			noError(t, err)
			client, err := f.auth.CreateGroupOAuthClient(t.Context(), iam.SystemIdentity(), iam.GroupByID(group.ID), iam.NewOAuthClient{ClientName: "Customer proof", RedirectURIs: []string{"https://client.example/callback"}, TokenEndpointAuthMethod: iam.OAuthClientNone, Scope: "openid customer:self"})
			noError(t, err)
			header, claims := jwtParts(t, session.AccessToken)
			header["typ"] = "at+jwt"
			claims["aud"], claims["client_id"], claims["scope"] = resource, client.ClientID, "customer:self"
			resourceToken := signJWT(t, f.deps.KeySource.ActiveSigner(), header, claims)
			resourceVerified, _ := liveProofRequest(t, f.auth.Authenticator(), resourceToken, nil)
			if resourceVerified.(auth.Bound).BoundScope().ID != group.ID {
				t.Fatal("registered resource client lost its controlling group")
			}
			noError(t, liveChecker(t, resourceVerified).CheckCredential(t.Context()))
			header, claims = jwtParts(t, session.AccessToken)
			claims["group_id"] = group.ID
			native, _ := liveProofRequest(t, f.auth.Authenticator(), signJWT(t, f.deps.KeySource.ActiveSigner(), header, claims), nil)
			noError(t, liveChecker(t, native).CheckCredential(t.Context()))
			noError(t, f.auth.DeleteGroupOAuthClient(t.Context(), iam.SystemIdentity(), iam.GroupByID(group.ID), client.ClientID))
			requireRevokedCredential(t, liveChecker(t, resourceVerified))
			noError(t, liveChecker(t, native).CheckCredential(t.Context()))
			noError(t, f.auth.DeleteGroup(t.Context(), iam.GroupByID(group.ID)))
			requireRevokedCredential(t, liveChecker(t, native))
		})
	})
}
