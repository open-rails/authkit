package critical_test

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/open-rails/authkit"
	"github.com/open-rails/authkit/auth"
	"github.com/open-rails/authkit/authtest"
	"github.com/open-rails/authkit/iam"
)

func TestCriticalTenantDispatch(t *testing.T) {
	t.Run("AK-J02-C06_native_directory_dispatch_preserves_proofs_and_scope", func(t *testing.T) {
		isolatedID := iam.NewTenantID()
		unknownID := iam.NewTenantID()
		var platformID iam.TenantID
		f := newFixture(t,
			authtest.WithConfig(func(c *authkit.Config) { c.SignIn.DPoP = authkit.DPoPRequired }),
			authtest.WithDeps(func(d *authkit.Deps) {
				d.RequestTenant = func(r *http.Request) (iam.TenantID, error) {
					switch r.Header.Get("X-Critical-Directory") {
					case "isolated":
						return isolatedID, nil
					case "platform":
						return platformID, nil
					case "unknown":
						return unknownID, nil
					case "refused":
						return iam.TenantID{}, auth.ErrForbidden
					case "failed":
						return iam.TenantID{}, errors.New("host directory registry unavailable")
					}
					return iam.TenantID{}, nil
				}
			}))
		platformID = f.tenant
		noError(t, f.auth.CreateTenant(t.Context(), iam.Tenant{ID: isolatedID, Slug: "isolated"}))
		isolated, err := f.auth.ForTenant(t.Context(), isolatedID)
		noError(t, err)
		platform := f.user(t)
		private, err := isolated.CreateUser(t.Context(), iam.NewUser{Email: platform.Email, Username: "isolatedperson", Password: platform.Password, EmailVerified: true})
		noError(t, err)
		key := authtest.NewDPoPKey(t)
		loginBody := map[string]string{"identifier": platform.Email, "password": platform.Password}
		loginHeaders := func(selector string) http.Header {
			return http.Header{"X-Critical-Directory": {selector}, "DPoP": {key.Proof(t, "POST", authtest.Issuer+f.auth.APIBase()+"/password/login", "", "")}}
		}
		for _, mounting := range []string{"handler", "route_catalog"} {
			t.Run(mounting, func(t *testing.T) {
				if mounting == "route_catalog" {
					previous := f.server
					defer func() { f.server = previous }()
					mux := http.NewServeMux()
					noError(t, f.auth.Mount(mux))
					f.server = httptest.NewServer(mux)
					t.Cleanup(f.server.Close)
				}
				for _, directory := range []struct{ selector, userID string }{{"", platform.ID}, {"isolated", private.ID}} {
					headers := loginHeaders(directory.selector)
					r, err := f.requestHeaders(t.Context(), "POST", "/password/login", "", loginBody, headers)
					noError(t, err)
					token := tokensFrom(t, r, directory.userID).AccessToken
					// The selected directory never reidentifies a valid session.
					wrong := "isolated"
					if directory.selector == "isolated" {
						wrong = "platform"
					}
					for _, target := range []string{wrong, directory.selector} {
						proof := http.Header{"X-Critical-Directory": {target}, "Authorization": {"DPoP " + token}, "DPoP": {key.Proof(t, "GET", authtest.Issuer+f.auth.APIBase()+"/me", token, "")}}
						me, err := f.requestHeaders(t.Context(), "GET", "/me", "", nil, proof)
						noError(t, err)
						if target == wrong {
							me.want(t, http.StatusForbidden, "forbidden")
							continue
						}
						me.want(t, http.StatusOK, "")
						var profile struct{ ID string }
						decode(t, me.body, &profile)
						if profile.ID != directory.userID {
							t.Fatal("selected directory changed the session's account")
						}
					}
				}
			})
		}
		for _, refusal := range []struct {
			selector, code string
			status         int
		}{{"unknown", "not_found", http.StatusNotFound}, {"refused", "forbidden", http.StatusForbidden}, {"failed", "internal_error", http.StatusInternalServerError}} {
			t.Run(refusal.selector, func(t *testing.T) {
				headers := loginHeaders(refusal.selector)
				r, err := f.requestHeaders(t.Context(), "POST", "/password/login", "", loginBody, headers)
				noError(t, err)
				r.want(t, refusal.status, refusal.code)
				// A refused selection did not spend the anonymous proof. The
				// exact proof can reach the intended directory once, then fails replay.
				headers.Set("X-Critical-Directory", "isolated")
				r, err = f.requestHeaders(t.Context(), "POST", "/password/login", "", loginBody, headers)
				noError(t, err)
				tokensFrom(t, r, private.ID)
				r, err = f.requestHeaders(t.Context(), "POST", "/password/login", "", loginBody, headers)
				noError(t, err)
				r.want(t, http.StatusUnauthorized, "sender_proof_required")
			})
		}
		t.Run("pinned_view", func(t *testing.T) {
			f.server = httptest.NewServer(isolated.Handler())
			t.Cleanup(f.server.Close)
			headers := loginHeaders("platform")
			r, err := f.requestHeaders(t.Context(), "POST", "/password/login", "", loginBody, headers)
			noError(t, err)
			r.want(t, http.StatusForbidden, "forbidden")
			// No selection preserves the explicitly pinned directory and proof.
			headers.Del("X-Critical-Directory")
			r, err = f.requestHeaders(t.Context(), "POST", "/password/login", "", loginBody, headers)
			noError(t, err)
			tokensFrom(t, r, private.ID)
		})
	})
}
