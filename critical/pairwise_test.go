package critical_test

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/open-rails/authkit"
	"github.com/open-rails/authkit/auth"
	"github.com/open-rails/authkit/authtest"
	"github.com/open-rails/authkit/iam"
)

// TestCriticalPairwiseSubjects covers "Sign in with" a network whose
// merchants register their own clients: with pairwise subjects no two
// merchants can join their buyers, and the network still knows each one.
func TestCriticalPairwiseSubjects(t *testing.T) {
	t.Run("AK-J43-C01_each_group_knows_a_user_and_sign_in_by_its_own_ids_and_only_the_network_maps_them_back", func(t *testing.T) {
		const resource = "https://network-api.example"
		const redirect = "https://shop.example/callback"
		var selected atomic.Pointer[http.Handler]
		front := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if h := selected.Load(); h != nil {
				(*h).ServeHTTP(w, r)
				return
			}
			http.Error(w, "starting", http.StatusServiceUnavailable)
		}))
		t.Cleanup(front.Close)
		var persona iam.Persona
		f := newFixture(t, authtest.WithConfig(func(c *authkit.Config) {
			c.Issuer = front.URL
			persona = c.Roles.Persona("merchant", authkit.OAuthClients).Persona
			c.Resource = authkit.ResourceConfig{ID: resource, Scopes: map[string][]string{"customer:self": {}}}
			c.AuthorizationServer.Resources = []authkit.ResourceServerConfig{{ID: resource, Scopes: []string{"customer:self"}}}
			c.AuthorizationServer.GroupClients.Scopes = []authkit.GroupClientScope{{Name: "customer:self", Resource: resource, Description: "Pay with saved cards"}}
			c.AuthorizationServer.GroupClients.PairwiseSubjects = true
		}))
		h := f.auth.Handler()
		selected.Store(&h)
		caller := &fixture{auth: f.auth, server: front, t: t, dpop: f.dpop, cfg: f.cfg}
		as := authtest.Attach(t, f.auth, front)
		u := f.user(t)
		session := caller.signIn(t, u)
		_, sessionClaims := jwtParts(t, session.AccessToken)
		realSID, _ := sessionClaims["sid"].(string)

		merchant := func() iam.Group {
			owner := iam.UserSubject(f.user(t).ID)
			g, err := f.auth.CreateGroup(t.Context(), iam.NewGroup{Persona: persona, Owner: &owner})
			noError(t, err)
			return g
		}
		client := func(g iam.Group) iam.OAuthClientCreated {
			c, err := f.auth.CreateGroupOAuthClient(t.Context(), iam.SystemIdentity(), iam.GroupByID(g.ID), iam.NewOAuthClient{ClientName: "Shop",
				RedirectURIs: []string{redirect}, TokenEndpointAuthMethod: iam.OAuthClientSecretBasic, Scope: "openid email customer:self"})
			noError(t, err)
			return c
		}
		signIn := func(c iam.OAuthClientCreated) authtest.OAuthTokens {
			return as.AuthorizeAs(t, session, authtest.CodeFlow{ClientID: c.ClientID, ClientSecret: *c.ClientSecret, RedirectURI: redirect,
				Scopes: []string{"openid", "email", "customer:self"}, Consent: true, DPoP: newFixtureKey(t)})
		}
		a, b := merchant(), merchant()
		a1, a2, b1 := client(a), client(a), client(b)
		ta1, ta2, tb1 := signIn(a1), signIn(a2), signIn(b1)

		ids := func(tokens authtest.OAuthTokens) (sub, sid string) {
			_, id := jwtParts(t, tokens.IDToken)
			_, access := jwtParts(t, tokens.AccessToken)
			if id["sub"] != access["sub"] || id["sid"] != access["sid"] {
				t.Fatalf("ID and access token disagree: %v %v", id, access)
			}
			for _, raw := range []string{tokens.IDToken, tokens.AccessToken} {
				_, claims := jwtParts(t, raw)
				body, err := json.Marshal(claims)
				noError(t, err)
				if strings.Contains(string(body), u.ID) || strings.Contains(string(body), realSID) {
					t.Fatalf("a client's token names the user or session id: %s", body)
				}
			}
			sub, _ = id["sub"].(string)
			sid, _ = id["sid"].(string)
			return sub, sid
		}
		subA1, sidA1 := ids(ta1)
		subA2, sidA2 := ids(ta2)
		subB1, sidB1 := ids(tb1)
		if subA1 == "" || sidA1 == "" || subA1 != subA2 || sidA1 != sidA2 {
			t.Fatalf("one merchant's clients disagree: %s/%s and %s/%s", subA1, sidA1, subA2, sidA2)
		}
		if subA1 == subB1 || sidA1 == sidB1 {
			t.Fatal("two merchants got the same subject or sid")
		}
		if again, _ := ids(as.Refresh(t, a1.ClientID, *a1.ClientSecret, ta1)); again != subA1 {
			t.Fatalf("a refresh changed the subject: %s, then %s", subA1, again)
		}

		verified, err := f.auth.VerifyIDToken(t.Context(), tb1.IDToken)
		noError(t, err)
		if verified.Subject != subB1 || verified.UserID != u.ID || verified.SessionID != realSID || verified.GroupID != b.ID {
			t.Fatalf("VerifyIDToken: %+v", verified)
		}
		var info map[string]any
		r := oauthGet(t, as, "/oauth2/userinfo", ta1.AccessToken)
		r.want(t, http.StatusOK, "")
		decode(t, r.body, &info)
		if info["sub"] != subA1 || info["email"] != u.Email {
			t.Fatalf("userinfo: %s", r.body)
		}
		v, _ := liveProofRequest(t, f.auth.Authenticator(), tb1.AccessToken, nil)
		if v.Identity().Subject != u.ID || v.(auth.Bound).BoundScope().ID != b.ID {
			t.Fatalf("the network's resource server saw %+v", v.Identity())
		}
		var metadata struct {
			SubjectTypes []string `json:"subject_types_supported"`
		}
		r = oauthGet(t, as, iam.OpenIDConfigurationPath, "")
		r.want(t, http.StatusOK, "")
		decode(t, r.body, &metadata)
		if !slices.Contains(metadata.SubjectTypes, "pairwise") {
			t.Fatalf("discovery: %s", r.body)
		}

		// One merchant's ID token ends the sign-in every merchant shares.
		r = oauthGet(t, as, "/oauth2/end_session?"+url.Values{"id_token_hint": {tb1.IDToken}}.Encode(), "")
		r.want(t, http.StatusSeeOther, "")
		if _, err := f.auth.VerifyIDToken(t.Context(), ta1.IDToken); !errors.Is(err, iam.ErrInvalidIDToken) {
			t.Fatalf("an ended sign-in's ID token verified: %v", err)
		}
		oauthGet(t, as, "/oauth2/userinfo", ta1.AccessToken).want(t, http.StatusUnauthorized, "")
	})
}

// oauthGet is a GET of the authorization server's path, with a bearer token.
func oauthGet(t *testing.T, as *authtest.AuthorizationServer, path, bearer string) response {
	t.Helper()
	r, err := http.NewRequestWithContext(t.Context(), http.MethodGet, as.URL+path, nil)
	noError(t, err)
	if bearer != "" {
		authorize(t, r, bearer)
	}
	res, err := as.HTTPClient().Do(r)
	noError(t, err)
	defer res.Body.Close()
	var body json.RawMessage
	_ = json.NewDecoder(res.Body).Decode(&body)
	return response{status: res.StatusCode, header: res.Header, body: body}
}
