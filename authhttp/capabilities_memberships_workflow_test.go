package authhttp

import (
	"encoding/json"
	"net/http"
	"testing"

	authkit "github.com/open-rails/authkit"
	"github.com/open-rails/authkit/authprovider"
	"github.com/open-rails/authkit/embedded"
	"github.com/open-rails/authkit/internal/testdb"
	"github.com/stretchr/testify/require"
)

func TestCapabilitiesAndRootMembershipDiscovery(t *testing.T) {
	pg := testdb.ScratchPostgres(t)
	cfg := newServerTestConfig()
	cfg.TwoFactor.Mode = embedded.TwoFactorDisabled
	cfg.RBAC = []embedded.PersonaDef{embedded.IntrinsicRootPersona(embedded.RoleDef{Name: "reader", Permissions: []string{"root:posts:read"}})}
	f := newAccountFlow(t, pg.Pool, cfg)
	setTestProviders(f.service, authprovider.Google("google-client", "secret"), authprovider.Discord("discord-client", "secret"))
	f.mount()
	caps := f.expect(http.StatusOK, f.request(http.MethodGet, "/capabilities", "", nil))
	var wire map[string]json.RawMessage
	require.NoError(t, json.Unmarshal([]byte(caps.raw), &wire))
	require.NotContains(t, wire, "providers")
	var providers []AuthProviderSummary
	require.NoError(t, json.Unmarshal(wire["external_login_providers"], &providers))
	require.Equal(t, []AuthProviderSummary{{ID: "discord", Name: "Discord", SupportsLogin: true, SupportsRegistration: true, SupportsLink: true}, {ID: "google", Name: "Google", SupportsLogin: true, SupportsRegistration: true, SupportsLink: true}}, providers)
	f.expect(http.StatusUnauthorized, f.request(http.MethodGet, "/me/groups", "", nil))
	register := func(name string) authkit.TokenSet {
		t.Helper()
		response := f.expect(http.StatusAccepted, f.post("/register", map[string]any{"identifier": name + "@example.test", "username": name, "password": "Correct-horse-membership-password-1"}))
		return response.Tokens
	}
	alice, bob := register("membersalice"), register("membersbob")
	type membership struct {
		GroupID string `json:"group_id"`
		Persona string `json:"persona"`
		Role    string `json:"role"`
	}
	groups := func(token, query string) []membership {
		t.Helper()
		response := f.expect(http.StatusOK, f.request(http.MethodGet, "/me/groups"+query, token, nil))
		var list struct {
			Data []membership `json:"data"`
		}
		require.NoError(t, json.Unmarshal([]byte(response.raw), &list))
		require.NotNil(t, list.Data, "empty membership is an array, not null")
		return list.Data
	}
	require.Empty(t, groups(alice.AccessToken, ""))
	claims, err := f.service.Verifier().Verify(t.Context(), alice.AccessToken)
	require.NoError(t, err)
	require.NoError(t, f.service.svc.OperatorAssignGroupRole(t.Context(), authkit.RootGroup(), authkit.UserSubject(claims.UserID), "reader"))
	got := groups(alice.AccessToken, "")
	require.Len(t, got, 1)
	require.NotEmpty(t, got[0].GroupID)
	require.Equal(t, "root", got[0].Persona)
	require.Equal(t, "reader", got[0].Role)
	require.Empty(t, groups(bob.AccessToken, "?user_id="+claims.UserID), "caller cannot select another user's memberships")
	require.NoError(t, f.service.svc.OperatorUnassignGroupRole(t.Context(), authkit.RootGroup(), authkit.UserSubject(claims.UserID), "reader"))
	require.Empty(t, groups(alice.AccessToken, ""), "membership discovery reads current assignments")
}
