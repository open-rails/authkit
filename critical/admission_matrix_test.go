package critical_test

import (
	"net/http"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/open-rails/authkit"
	"github.com/open-rails/authkit/authtest"
	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/notify"
	"github.com/open-rails/authkit/provider"
)

// openSCIM are the SCIM routes anyone may read: the directory's discovery
// documents. Every other SCIM route authenticates its own credential.
var openSCIM = map[string]bool{
	"/directory/scim/v2/ServiceProviderConfig": true,
	"/directory/scim/v2/ResourceTypes":         true,
	"/directory/scim/v2/ResourceTypes/{id}":    true,
	"/directory/scim/v2/Schemas":               true,
	"/directory/scim/v2/Schemas/{id}":          true,
}

func fullSurfaceFixture(t *testing.T) *fixture {
	t.Helper()
	var publish iam.Perm
	f := newFixture(t, authtest.WithConfig(func(c *authkit.Config) {
		publish = c.Roles.Tenant.Permission("notifications", "publish")
		c.TwoFactor = iam.TwoFactorOptional
		mountGroups(c, iam.RouteDeviceKeys)
		c.SolanaNetwork = iam.SolanaMainnet
		c.Roles.Persona("oauthshop", authkit.OAuthClients)
		c.AuthorizationServer.Clients = []authkit.OAuthClientConfig{{ID: "browser", RedirectURIs: []string{"https://client.example/callback"}}}
	}), authtest.WithDeps(func(d *authkit.Deps) {
		// Only protected routes are exercised: this real provider configuration
		// must never make a discovery/token request for rejected credentials.
		d.Providers = []provider.Provider{provider.Google("critical-client", "critical-secret")}
	}))
	// A producer, so its route reaches the live authority check it guards.
	_, err := f.auth.Notifications(authkit.NotificationProducer{Name: "probe", Origin: notify.OriginScope{System: "probe", Scope: "probe"},
		PermissionGroupID: f.tenant.String(), Permission: publish.String()})
	noError(t, err)
	f.notify = publish
	return f
}

func TestCriticalHTTPAdmission(t *testing.T) {
	t.Run("AK-J31-C01_every_mounted_route_refuses_credentials_its_tier_does_not_admit", func(t *testing.T) {
		f := fullSurfaceFixture(t)
		group, target, _ := f.ownedGroup(t)
		owner := iam.UserSubject(target.ID)
		var oauthPersona iam.Persona
		noError(t, oauthPersona.UnmarshalText([]byte("oauthshop")))
		oauthGroup, err := f.auth.CreateGroup(t.Context(), iam.NewGroup{Persona: oauthPersona, Owner: &owner})
		noError(t, err)
		outsider := f.user(t)
		session := f.signIn(t, outsider)
		h, cl := jwtParts(t, session.AccessToken)
		cl["exp"] = time.Now().Add(-2 * time.Minute).Unix()
		cl["iat"] = time.Now().Add(-time.Hour).Unix()
		expired := signJWT(t, f.deps.KeySource.ActiveSigner(), h, cl)
		revoked := f.signIn(t, outsider)
		claims, err := verifyToken(t, f.auth, revoked.AccessToken)
		noError(t, err)
		noError(t, f.auth.RevokeSession(t.Context(), iam.SystemIdentity(), outsider.ID, claims.SessionID))
		// Every mounted route is probed by the tier it declares (api/openapi.json
		// pins each route's tier): a route added without its gate fails here.
		param := regexp.MustCompile(`\{[a-z_]+\}`)
		probed := map[string]int{}
		for _, route := range f.auth.Routes() {
			gate := string(route.Auth)
			if route.Group == iam.RouteSCIM && !openSCIM[route.Path] {
				gate = "scim"
			}
			if route.Method == http.MethodHead || route.Method == http.MethodOptions || gate == string(iam.AuthPublic) {
				continue
			}
			probed[gate]++
			t.Run(route.Method+route.Path, func(t *testing.T) {
				path := strings.NewReplacer("{group_id}", group.ID, "{user_id}", target.ID, "{id}", target.ID, "{kind}", "users", "{role}", f.reader.String(), "{provider}", "google", "{client_id}", "browser", "{authorization_id}", target.ID, "{tenant_id}", f.tenant.String(), "{slug}", "probe", "{producer}", "probe").Replace(route.Path)
				path = param.ReplaceAllString(path, iam.NewTenantID().String())
				if strings.Contains(route.Path, "/oauth-clients") {
					path = strings.Replace(path, group.ID, oauthGroup.ID, 1)
				}
				mediaType := "application/json"
				body := "{}"
				if route.Method == "GET" || route.Method == "DELETE" {
					body = ""
				}
				for _, cred := range []struct{ name, token string }{{"anonymous", ""}, {"malformed", "not-a-token"}, {"expired", expired}} {
					if gate == string(iam.AuthOptional) && cred.token == "" {
						continue
					} // anonymous confirmation uses its delivered proof
					t.Run(cred.name, func(t *testing.T) {
						r := wire(t, f.server.Client(), route.Method, f.server.URL+path, cred.token, mediaType, body, nil)
						r.want(t, http.StatusUnauthorized, "")
						if gate == "scim" {
							var envelope struct {
								Status  string   `json:"status"`
								Schemas []string `json:"schemas"`
							}
							decode(t, r.body, &envelope)
							if envelope.Status != "401" || len(envelope.Schemas) != 1 || envelope.Schemas[0] != "urn:ietf:params:scim:api:messages:2.0:Error" {
								t.Fatal("SCIM rejection lost its protocol error envelope")
							}
						} else {
							var envelope iam.ErrorEnvelope
							decode(t, r.body, &envelope)
							if envelope.Error.Code == "" {
								t.Fatal("JSON rejection lost its public error code")
							}
						}
					})
				}
				if route.Auth == iam.AuthSession || route.Auth == iam.AuthPermission {
					t.Run("revoked_session", func(t *testing.T) {
						wire(t, f.server.Client(), route.Method, f.server.URL+path, revoked.AccessToken, mediaType, body, nil).want(t, 401, "session_revoked")
					})
				}
				if route.Auth == iam.AuthPermission || strings.HasPrefix(path, "/auth/v1/groups/") || strings.HasPrefix(path, "/auth/v1/admin/") || path == "/auth/v1/events" {
					t.Run("unprivileged_live_session", func(t *testing.T) {
						if route.Method == "PATCH" && strings.Contains(path, "/admin/users/") {
							body = `{"preferred_language":"en"}`
						}
						if route.Method == "PUT" && strings.HasSuffix(path, "/ban") {
							body = `{"reason":"unauthorized"}`
						}
						wire(t, f.server.Client(), route.Method, f.server.URL+path, session.AccessToken, mediaType, body, nil).want(t, 403, "")
					})
				}
			})
		}
		total := 0
		for _, gate := range []string{"required", "session", "permission", "optional", "scim"} {
			if probed[gate] == 0 {
				t.Errorf("no mounted route declares the %s tier", gate)
			}
			total += probed[gate]
		}
		if total < 100 {
			t.Fatalf("probed %d routes, want the full mounted surface: %v", total, probed)
		}
		for _, operation := range []struct {
			method, path, form string
			status             int
			code               string
		}{
			{"POST", "/oauth2/token", "grant_type=client_credentials&client_id=browser&client_secret=wrong-secret", 401, "invalid_client"},
			{"POST", "/oauth2/revoke", "token=not-a-token&client_id=browser&client_secret=wrong-secret", 401, "invalid_client"},
			{"GET", "/oauth2/userinfo", "", 401, "invalid_token"},
			{"POST", "/oauth2/userinfo", "", 401, "invalid_token"},
		} {
			t.Run(operation.method+operation.path+"_protocol_proof_required", func(t *testing.T) {
				r := wire(t, f.server.Client(), operation.method, f.server.URL+operation.path, "", "application/x-www-form-urlencoded", operation.form, nil)
				r.want(t, operation.status, "")
				var envelope struct {
					Error string `json:"error"`
				}
				decode(t, r.body, &envelope)
				if envelope.Error != operation.code {
					t.Fatalf("OAuth error=%s want%s", envelope.Error, operation.code)
				}
			})
		}
		// Known valid controls prevent blanket refusal from satisfying the matrix.
		f.call(t, "GET", "/me", session.AccessToken, nil).want(t, 200, "")
		f.call(t, "PATCH", "/me", session.AccessToken, map[string]string{"preferred_language": "en"}).want(t, 200, "")
		user, err := f.auth.User(t.Context(), iam.UserByID(target.ID))
		noError(t, err)
		if user.DeletedAt != nil || user.Ban != nil {
			t.Fatal("unauthorized directory operations changed their target")
		}
	})
}
