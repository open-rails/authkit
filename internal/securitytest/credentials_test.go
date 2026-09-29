package securitytest

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/open-rails/authkit"
	"github.com/open-rails/authkit/iam"
	"github.com/stretchr/testify/require"
)

// TestSecurityDeadCreatorCredentials (H1): banning or deleting an account ends
// its API keys on the host's own routes and its invite links at once; the
// credentials never outlive the account that issued them.
func TestSecurityDeadCreatorCredentials(t *testing.T) {
	h := newHost(t, withHTTP(generousLimits), withEngine(withRBAC), withEngine(func(c *authkit.Config) {
		c.Roles.Roles = append(c.Roles.Roles, authkit.Role{Persona: iam.RootPersona, Name: "staff", Permissions: append(iam.IntrinsicRootPermissions(), "org:*")})
	}))
	staff, founder := h.newAccount("staff"), h.newAccount("founder")
	h.grant(iam.RootGroup(), staff, "staff")
	staffToken := h.login(staff).AccessToken
	group, base := h.newOrg("h1", founder)
	gate := h.auth.Require(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) }))
	hostRoute := func(token string) int {
		r := httptest.NewRequest(http.MethodGet, "https://host.security.test/orders", nil)
		r.Header.Set("Authorization", "Bearer "+token)
		w := httptest.NewRecorder()
		gate.ServeHTTP(w, r)
		return w.Code
	}
	for _, end := range []struct {
		name string
		req  func(id string) request
	}{
		{"ban", func(id string) request {
			return request{method: http.MethodPost, path: "/admin/users/" + id + "/ban", body: map[string]any{"until": "infinite", "reason": "spam"}, token: staffToken}
		}},
		{"delete", func(id string) request {
			return request{method: http.MethodDelete, path: "/admin/users/" + id, token: staffToken}
		}},
	} {
		t.Run(end.name, func(t *testing.T) {
			creator := h.newAccount("creator")
			h.grant(group, creator, "manager")
			token := h.login(creator).AccessToken
			key := h.issue(base+"/api-keys", token, map[string]any{"name": "ci", "role": "member"})
			link := h.issue(base+"/invites/links", token, map[string]any{"role": "member"})
			require.Equal(t, http.StatusNoContent, hostRoute(key.Secret), "control: the key works while its creator is live")

			resp := h.do(end.req(creator.id))
			require.Less(t, resp.status, 300, resp.String())
			require.Equal(t, http.StatusUnauthorized, hostRoute(key.Secret))
			stranger := h.newAccount("stranger")
			resp = h.post("/invites/redeem", map[string]string{"code": link.Code}, h.login(stranger).AccessToken)
			require.GreaterOrEqual(t, resp.status, 400, resp.String())
			roles, err := h.auth.GroupRoles(context.Background(), group, []iam.Subject{iam.UserSubject(stranger.id)})
			require.NoError(t, err)
			require.Empty(t, roles, "a dead creator's link admitted a stranger")
		})
	}
}
