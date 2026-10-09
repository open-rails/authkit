package securitytest

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/open-rails/authkit"
	authkitgin "github.com/open-rails/authkit/adapters/gin"
	"github.com/open-rails/authkit/authtest"
	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/ident"
	"github.com/open-rails/authkit/internal/testdpop"
	"github.com/open-rails/authkit/verify"
	neutral "github.com/open-rails/helpers/auth"
	"github.com/stretchr/testify/require"
)

// serveGin serves AuthKit mounted on a Gin engine, plus the host's routes,
// in place of h's server.
func serveGin(t *testing.T, h *host, routes func(*gin.Engine)) {
	t.Helper()
	gin.SetMode(gin.TestMode)
	engine := gin.New()
	require.NoError(t, authkitgin.Mount(engine, h.auth))
	routes(engine)
	server := httptest.NewServer(engine)
	t.Cleanup(server.Close)
	h.server = server
}

// TestSecurityAuthenticateBehindGate: host code behind a gate authenticates
// the request again, as helpers/auth code does, with verify.AuthenticateRequest
// and then AuthenticateSession. Over real HTTP through the Gin adapter both
// reuse the gate's verification, so a DPoP proof is spent and the request
// verified once. AuthenticateSession refuses a credential whose sign-in was
// revoked, which the stateless gate admits, and a delegation minted without
// one; it passes an API key, which carries no sign-in.
func TestSecurityAuthenticateBehindGate(t *testing.T) {
	const resource = "resource.security.test"
	ban := iam.Perm(ident.RootUsersBan)
	h := newHost(t, withHTTP(generousLimits), authtest.WithConfig(withRBAC), authtest.WithConfig(func(c *authkit.Config) {
		c.Delegated = authkit.DelegatedConfig{Audiences: []string{resource}, AllowDPoP: true}
	}), authtest.WithDeps(func(d *authkit.Deps) {
		d.DelegatedAuthorization = func(context.Context, iam.DelegationRequest) (iam.DelegationGrant, error) {
			return iam.DelegationGrant{Permissions: []string{ban.String()}}, nil
		}
	}))
	verifier, err := h.auth.NewVerifier([]string{resource})
	require.NoError(t, err)
	auth := &countingAuthority{Authority: verifier}

	authenticate := func(c *gin.Context) {
		ctx := c.Request.Context()
		p, err := verify.AuthenticateRequest(ctx, auth, c.Request)
		if err == nil {
			p, err = verify.AuthenticateSession(ctx, auth, c.Request)
		}
		switch {
		case err == nil:
			c.String(http.StatusOK, p.Identity().Subject)
		case errors.Is(err, neutral.ErrRevoked):
			c.String(http.StatusUnauthorized, "revoked")
		case errors.Is(err, neutral.ErrSenderProofRequired):
			c.String(http.StatusUnauthorized, "sender_proof_required")
		default:
			c.String(http.StatusInternalServerError, err.Error())
		}
	}
	gates := map[string]gin.HandlerFunc{
		"/required":   authkitgin.Required(auth),
		"/optional":   authkitgin.Optional(auth),
		"/session":    authkitgin.RequireSession(auth),
		"/permission": authkitgin.RequirePermissionOn(auth, iam.RootGroup(), ban),
	}
	serveGin(t, h, func(e *gin.Engine) {
		for path, gate := range gates {
			e.POST(path, gate, authenticate)
		}
		e.POST("/ungated", authenticate)
	})
	send := func(path string, header http.Header) response {
		auth.verified.Store(0)
		return h.do(request{method: http.MethodPost, path: "/" + path, header: header})
	}

	moderator := h.newAccount("gatemod")
	h.grant(iam.RootGroup(), moderator, "moderator")
	parent := h.login(moderator).AccessToken
	key := testdpop.Key(t)
	resp := h.do(request{method: http.MethodPost, path: "/delegated/token", token: parent,
		body:   map[string]any{"requested_grant": map[string]any{}, "audiences": []string{resource}},
		header: http.Header{"DPoP": {testdpop.Proof(t, key, http.MethodPost, issuer+apiPrefix+"/delegated/token", parent, nil)}}})
	require.Equal(t, http.StatusOK, resp.status, resp.String())
	var minted struct {
		Token string `json:"access_token"`
	}
	resp.json(t, &minted)
	proven := func(path string) http.Header {
		return http.Header{
			"Authorization": {"DPoP " + minted.Token},
			"DPoP":          {testdpop.Proof(t, key, http.MethodPost, issuer+path, minted.Token, nil)},
		}
	}

	t.Run("a DPoP proof is spent once", func(t *testing.T) {
		for path := range gates {
			resp := send(path, proven(path))
			require.Equal(t, http.StatusOK, resp.status, "%s: %s", path, resp)
			require.Equal(t, moderator.id, resp.String(), path)
			require.EqualValues(t, 1, auth.verified.Load(), "%s: the host's calls verified the request again", path)
		}
		// With no gate there is nothing to reuse: the second call is a replay.
		resp := send("/ungated", proven("/ungated"))
		require.Equal(t, "sender_proof_required", resp.String())
		require.EqualValues(t, 2, auth.verified.Load())
	})

	t.Run("an API key carries no sign-in", func(t *testing.T) {
		owner, manager := h.newAccount("gateowner"), h.newAccount("gatemanager")
		group, base := h.newOrg(owner)
		h.grant(group, manager, "manager")
		apiKey := h.issue(base+"/api-keys", h.login(manager).AccessToken, map[string]any{"name": "ci", "role": "org:member"})
		resp := send("/required", http.Header{"Authorization": {"Bearer " + apiKey.Secret}})
		require.Equal(t, http.StatusOK, resp.status, resp.String())
		require.Equal(t, group.ID(), resp.String(), "the key is a credential of its group's account")
		require.EqualValues(t, 1, auth.verified.Load())
	})

	t.Run("a delegation minted without a sign-in", func(t *testing.T) {
		token, err := h.auth.MintDelegatedAccessToken(t.Context(), iam.SystemActor(), iam.DelegatedAccess{Subject: moderator.id, Audiences: []string{resource}})
		require.NoError(t, err)
		resp := send("/required", http.Header{"Authorization": {"Bearer " + token.Value}})
		require.Equal(t, "revoked", resp.String())
	})

	t.Run("a revoked sign-in", func(t *testing.T) {
		require.Equal(t, http.StatusNoContent, h.do(request{method: http.MethodDelete, path: "/logout", token: parent}).status)
		resp := send("/required", proven("/required"))
		require.Equal(t, http.StatusUnauthorized, resp.status, "the stateless gate admits it, AuthenticateSession does not: %s", resp)
		require.Equal(t, "revoked", resp.String())
		require.EqualValues(t, 1, auth.verified.Load())
	})
}

// TestSecurityPermissionReadMatchesMePermissions: a host expands a root role
// over its declared catalog with no database read (Client.RolePermissions,
// then PersonaDef.Expand) and gets what GET /me/permissions answers, for the
// owner, a moderator and a plain user, over real HTTP through the Gin adapter.
// Expanding the live grants (Client.EffectivePermissions) agrees.
func TestSecurityPermissionReadMatchesMePermissions(t *testing.T) {
	model := newSecurityModel()
	root := model.Roles.Root
	h := newHost(t, withHTTP(generousLimits), authtest.WithConfig(func(c *authkit.Config) { c.Roles = model.Roles }))
	type permissionSet struct {
		Role        *string  `json:"role"`
		Permissions []string `json:"permissions"`
	}
	serveGin(t, h, func(e *gin.Engine) {
		e.GET("/host/permissions", authkitgin.Required(h.auth), func(c *gin.Context) {
			cl, _ := verify.ClaimsFromContext(c.Request.Context())
			set := permissionSet{Permissions: []string{}}
			if role, err := h.auth.Role(cl.RootRole); err == nil {
				grants, err := h.auth.RolePermissions(role)
				if err != nil {
					c.String(http.StatusInternalServerError, err.Error())
					return
				}
				name := role.String()
				set = permissionSet{Role: &name, Permissions: ident.Strings(root.Expand(grants))}
			}
			c.JSON(http.StatusOK, set)
		})
	})

	owner, moderator, user := h.newAccount("readowner"), h.newAccount("readmod"), h.newAccount("readuser")
	h.grant(iam.RootGroup(), owner, "owner")
	h.grant(iam.RootGroup(), moderator, "moderator")
	for name, tc := range map[string]struct {
		account account
		role    string
		want    []iam.Perm
	}{
		"owner":      {owner, "root:owner", root.Permissions()},
		"moderator":  {moderator, "root:moderator", []iam.Perm{root.Users.Ban}},
		"plain user": {user, "", []iam.Perm{}},
	} {
		t.Run(name, func(t *testing.T) {
			token := h.login(tc.account).AccessToken
			var me, host permissionSet
			resp := h.get("/me/permissions", token)
			require.Equal(t, http.StatusOK, resp.status, resp.String())
			resp.json(t, &me)
			resp = h.do(request{method: http.MethodGet, path: "//host/permissions", token: token})
			require.Equal(t, http.StatusOK, resp.status, resp.String())
			resp.json(t, &host)

			require.Equal(t, ident.Strings(tc.want), me.Permissions)
			require.Equal(t, me.Permissions, host.Permissions)
			require.Equal(t, me.Role, host.Role)
			if tc.role == "" {
				require.Nil(t, me.Role)
			} else {
				require.Equal(t, tc.role, *me.Role)
			}

			cl, err := h.auth.Verify(t.Context(), token)
			require.NoError(t, err)
			actor, ok := verify.ActorFromClaims(cl)
			require.True(t, ok)
			byGroup, err := h.auth.EffectivePermissions(t.Context(), actor, []iam.GroupRef{iam.RootGroup()})
			require.NoError(t, err)
			var live []iam.Perm
			for _, grants := range byGroup {
				live = append(live, grants...)
			}
			require.Equal(t, me.Permissions, ident.Strings(root.Expand(live)))
		})
	}
	require.Contains(t, root.Permissions(), root.Users.Ban, "the catalog lists the built-ins")
}
