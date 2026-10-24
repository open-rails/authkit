package critical_test

import (
	_ "embed"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/open-rails/authkit"
	"github.com/open-rails/authkit/authtest"
	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/provider"
)

// Reviewed contract rows from tracker #1290. This is a fixed admission oracle,
// not generated from the running router. Public login/proof success contracts
// live in their stateful journeys; security-only rows do not claim full CRUD.
//
//go:embed testdata/route-admission.json
var admissionRows []byte

func fullSurfaceFixture(t *testing.T) *fixture {
	t.Helper()
	return newFixture(t, authtest.WithConfig(func(c *authkit.Config) {
		c.TwoFactor.Mode = iam.TwoFactorOptional
		c.Passkeys = authkit.PasskeyConfig{RPID: "example.com", Origins: []string{"https://example.com"}}
		c.DeviceKeys.Enabled = true
		c.SolanaNetwork = iam.SolanaMainnet
		c.Roles.Persona("oauthshop", authkit.OAuthClients)
		c.AuthorizationServer.Clients = []authkit.OAuthClientConfig{{ID: "browser", RedirectURIs: []string{"https://client.example/callback"}}}
	}), authtest.WithDeps(func(d *authkit.Deps) {
		// Only protected routes are exercised: this real provider configuration
		// must never make a discovery/token request for rejected credentials.
		d.Providers = []provider.Provider{provider.Google("critical-client", "critical-secret")}
	}))
}

func TestCriticalHTTPAdmission(t *testing.T) {
	t.Run("AK-J31-C01_selected_route_admission_and_live_scope_contracts", func(t *testing.T) {
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
		claims, err := f.auth.Verify(t.Context(), revoked.AccessToken)
		noError(t, err)
		noError(t, f.auth.RevokeSession(t.Context(), iam.SystemIdentity(), outsider.ID, claims.SessionID))
		var rows []struct{ ID, Method, Path, Gate, Coverage, Owner string }
		noError(t, json.Unmarshal(admissionRows, &rows))
		mounted := map[string]bool{}
		for _, route := range f.auth.Routes() {
			mounted[route.Method+" "+route.Path] = true
		}
		for _, row := range rows {
			t.Run(row.ID+"_"+row.Method+row.Path, func(t *testing.T) {
				if !mounted[row.Method+" "+row.Path] {
					t.Fatalf("contract route is not mounted: %s %s", row.Method, row.Path)
				}
				path := strings.NewReplacer("{group_id}", group.ID, "{user_id}", target.ID, "{id}", target.ID, "{kind}", "users", "{role}", f.reader.String(), "{provider}", "google", "{client_id}", "browser", "{authorization_id}", target.ID).Replace(row.Path)
				if strings.Contains(row.Path, "/oauth-clients") {
					path = strings.Replace(path, group.ID, oauthGroup.ID, 1)
				}
				mediaType := "application/json"
				body := "{}"
				if row.Method == "GET" || row.Method == "DELETE" {
					body = ""
				}
				for _, cred := range []struct{ name, token string }{{"anonymous", ""}, {"malformed", "not-a-token"}, {"expired", expired}} {
					if row.Gate == "optional" && cred.token == "" {
						continue
					} // anonymous confirmation uses its delivered proof
					t.Run(cred.name, func(t *testing.T) {
						r := wire(t, f.server.Client(), row.Method, f.server.URL+path, cred.token, mediaType, body, nil)
						r.want(t, http.StatusUnauthorized, "")
						if row.Gate == "scim" {
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
				if row.Gate == "session" || row.Gate == "permission" {
					t.Run("revoked_session", func(t *testing.T) {
						wire(t, f.server.Client(), row.Method, f.server.URL+path, revoked.AccessToken, mediaType, body, nil).want(t, 401, "session_revoked")
					})
				}
				if strings.HasPrefix(path, "/api/v1/groups/") || strings.HasPrefix(path, "/api/v1/admin/") || path == "/api/v1/events" {
					t.Run("unprivileged_live_session", func(t *testing.T) {
						if row.Method == "PATCH" && strings.Contains(path, "/admin/users/") {
							body = `{"preferred_language":"en"}`
						}
						if row.Method == "PUT" && strings.HasSuffix(path, "/ban") {
							body = `{"reason":"unauthorized"}`
						}
						wire(t, f.server.Client(), row.Method, f.server.URL+path, session.AccessToken, mediaType, body, nil).want(t, 403, "")
					})
				}
			})
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
