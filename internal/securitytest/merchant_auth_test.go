package securitytest

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/google/uuid"
	"github.com/open-rails/authkit"
	"github.com/open-rails/authkit/authtest"
	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/builtwith"
	"github.com/open-rails/authkit/internal/ident"
	"github.com/open-rails/authkit/verify"
	neutral "github.com/open-rails/helpers/auth"
	"github.com/stretchr/testify/require"
)

const (
	refund        = "merchant:payments:refund"
	customersRead = "root:customers:read"
)

// merchantRoles declares merchant permissions given whole (an AuthKit
// built-in among them), a support role holding refund exactly, a viewer
// holding only the merchant:*:read pattern, a root role holding every merchant
// permission, and a root staff role holding a host's own root permission.
func merchantRoles(c *authkit.Config) {
	r := authkit.NewRoles()
	m := r.Persona("merchant", authkit.APIKeys, authkit.RemoteApplications)
	p := m.Declare("merchant:payments:read", refund, "merchant:credits:grant", "merchant:members:read")
	m.Role("support", p[0], p[1])
	m.Role("viewer", ident.Perm("merchant:*:read"))
	r.Root.Role("billing", m.All())
	r.Root.Role("staff", r.Root.Permission("customers", "read"))
	c.Roles = r
	withDeviceKeys(c)
}

// gated serves a gate stack whose handler answers 200 with the identity the
// Client's Caller reports, or 299 when the gates admitted a request it
// reports none for.
func gated(a *authkit.Client, gates ...func(http.Handler) http.Handler) func(t *testing.T, header http.Header) response {
	var h http.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, ok := a.Identity(r.Context())
		if !ok {
			w.WriteHeader(299)
			return
		}
		_ = json.NewEncoder(w).Encode(c)
	})
	for i := len(gates) - 1; i >= 0; i-- {
		h = gates[i](h)
	}
	return sendTo(h)
}

func bearer(token string) http.Header { return http.Header{"Authorization": {"Bearer " + token}} }

func callerOf(t *testing.T, r response) neutral.Identity {
	t.Helper()
	require.Equal(t, http.StatusOK, r.status, r.String())
	var c neutral.Identity
	r.json(t, &c)
	return c
}

func requireStatus(t *testing.T, r response, status int, code string) {
	t.Helper()
	require.Equal(t, status, r.status, r.String())
	if code != "" {
		require.Equal(t, code, r.errorCode(), r.String())
	}
}

// TestSecurityMerchantAuth: the Client is the helpers/auth Auth a billing
// library (OpenRails) mounts merchant routes with. Required admits only a
// person, live; RequirePermission checks one concrete merchant permission,
// live, in exactly the group Config.Merchant names; Sensitive refuses a stale
// sign-in and every credential without one; Caller reports the identity only
// for claims a gate over the Client verified.
func TestSecurityMerchantAuth(t *testing.T) {
	ctx := context.Background()
	merchant := uuid.NewString()
	h := newHost(t, withHTTP(generousLimits), authtest.WithConfig(merchantRoles), authtest.WithConfig(func(c *authkit.Config) {
		c.Merchant.Group = merchant
	}))
	persona := ident.Persona("merchant")
	group := iam.GroupByID(merchant)
	owner, support, viewer := h.newAccount("mowner"), h.newAccount("msupport"), h.newAccount("mviewer")
	outsider, billing, banned := h.newAccount("moutsider"), h.newAccount("mbilling"), h.newAccount("mbanned")
	ownerSubject, outsiderSubject := iam.UserSubject(owner.id), iam.UserSubject(outsider.id)
	_, err := h.auth.CreateGroup(ctx, iam.NewGroup{ID: merchant, Persona: persona, Owner: &ownerSubject})
	require.NoError(t, err)
	_, err = h.auth.CreateGroup(ctx, iam.NewGroup{Persona: persona, Owner: &outsiderSubject})
	require.NoError(t, err)
	h.grant(group, support, "support")
	h.grant(group, banned, "support")
	h.grant(group, viewer, "viewer")
	h.grant(iam.RootGroup(), billing, "billing")

	apiKey := func(role string) string {
		_, secret, err := createKey(h.auth, ctx, iam.UserIdentity(owner.id), group, iam.NewAPIKey{Name: role, Role: roleIn(t, h.auth, group, role)})
		require.NoError(t, err)
		return secret
	}
	supportKey, viewerKey := apiKey("support"), apiKey("viewer")

	token := map[string]string{}
	for name, a := range map[string]account{"owner": owner, "support": support, "viewer": viewer, "outsider": outsider, "billing": billing, "banned": banned} {
		token[name] = h.login(a).AccessToken
	}
	pub, priv := ed25519Key(t)
	dk := h.deviceKeyClient()
	enrollment, err := dk.BeginEnrollment(ctx, support.email, pub, "laptop")
	require.NoError(t, err)
	device, err := dk.FinishEnrollment(ctx, enrollment, priv, h.verificationCode(support.email), "")
	require.NoError(t, err)
	require.NoError(t, h.auth.Ban(ctx, iam.SystemIdentity(), banned.id, iam.Ban{Reason: "fraud"}))

	required := gated(h.auth, h.auth.Required())
	permitted := gated(h.auth, h.auth.RequirePermission(refund))
	sensitive := gated(h.auth, h.auth.RequirePermission(refund), h.auth.Sensitive())

	t.Run("Required admits a person, live", func(t *testing.T) {
		requireStatus(t, required(t, http.Header{}), http.StatusUnauthorized, "unauthenticated")
		c := callerOf(t, required(t, bearer(token["support"])))
		require.Equal(t, support.id, c.Subject)
		require.Equal(t, neutral.SubjectUser, c.SubjectKind)
		require.Equal(t, neutral.CredentialSession, c.Credential.Kind)
		require.True(t, c.SelfInvoked())
		require.Equal(t, support.email, c.Email)
		c = callerOf(t, required(t, bearer(device.AccessToken)))
		require.Equal(t, support.id, c.Subject, "a device key's subject is its user")
		require.Equal(t, neutral.CredentialDeviceKey, c.Credential.Kind)
		requireStatus(t, required(t, bearer(token["banned"])), http.StatusUnauthorized, "session_revoked")
		requireStatus(t, required(t, bearer(supportKey)), http.StatusForbidden, "forbidden")
	})

	t.Run("RequirePermission checks the merchant group, live", func(t *testing.T) {
		requireStatus(t, permitted(t, http.Header{}), http.StatusUnauthorized, "unauthenticated")
		for _, name := range []string{"support", "owner", "billing"} {
			require.Equal(t, neutral.SubjectUser, callerOf(t, permitted(t, bearer(token[name]))).SubjectKind, name)
		}
		requireStatus(t, permitted(t, bearer(token["viewer"])), http.StatusForbidden, "forbidden")
		requireStatus(t, permitted(t, bearer(token["outsider"])), http.StatusForbidden, "forbidden")
		requireStatus(t, permitted(t, bearer(token["banned"])), http.StatusUnauthorized, "session_revoked")
		requireStatus(t, permitted(t, bearer(viewerKey)), http.StatusForbidden, "forbidden")

		c := callerOf(t, permitted(t, bearer(supportKey)))
		require.Equal(t, merchant, c.Subject, "a group API key is the group's account")
		require.Equal(t, neutral.SubjectApplication, c.SubjectKind)
		require.Equal(t, neutral.CredentialAPIKey, c.Credential.Kind)

		for _, pattern := range []string{"merchant:*", "merchant:payments:*", "merchant:*:read", "merchant:payments:void"} {
			require.Panics(t, func() { h.auth.RequirePermission(pattern) }, "%s is not one registered permission", pattern)
		}
	})

	t.Run("Sensitive refuses a stale sign-in and credentials without one", func(t *testing.T) {
		callerOf(t, sensitive(t, bearer(token["support"])))
		requireStatus(t, sensitive(t, bearer(authtest.StaleSession(t, h.auth, token["support"]))), http.StatusForbidden, "step_up_required")
		requireStatus(t, sensitive(t, bearer(supportKey)), http.StatusForbidden, "forbidden")
	})

	t.Run("only the Client's own gates prove an identity", func(t *testing.T) {
		forged := verify.Claims{Kind: verify.TokenUser, Issuer: issuer, UserID: owner.id, SessionID: uuid.NewString()}
		setClaims := func(next http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				next.ServeHTTP(w, r.WithContext(verify.SetClaims(r.Context(), forged)))
			})
		}
		requireStatus(t, gated(h.auth, setClaims)(t, http.Header{}), 299, "")
		requireStatus(t, gated(h.auth, setClaims, h.auth.RequirePermission(refund))(t, http.Header{}), http.StatusUnauthorized, "unauthenticated")
		c := callerOf(t, gated(h.auth, setClaims, h.auth.RequirePermission(refund))(t, bearer(token["support"])))
		require.Equal(t, support.id, c.Subject, "the gate verified the request, not the stored claims")

		verifier, err := h.auth.NewVerifier([]string{audience})
		require.NoError(t, err)
		requireStatus(t, gated(h.auth, verify.Required(verifier))(t, bearer(token["support"])), 299, "")
	})
}

// TestSecurityPermissionGroupIsInferred: a root: permission is checked on
// root with no configuration, and still on root when Config.Merchant.Group is
// set; a persona permission without Group refuses everyone; a pattern or an
// unregistered permission panics at construction; and New refuses
// Config.Merchant.Group naming the root group.
func TestSecurityPermissionGroupIsInferred(t *testing.T) {
	ctx := context.Background()
	unset := newHost(t, withHTTP(generousLimits), authtest.WithConfig(merchantRoles))
	staff, billing, owner := unset.newAccount("ustaff"), unset.newAccount("ubilling"), unset.newAccount("uowner")
	unset.grant(iam.RootGroup(), staff, "staff")
	unset.grant(iam.RootGroup(), billing, "billing")
	ownerSubject := iam.UserSubject(owner.id)
	merchant, err := unset.auth.CreateGroup(ctx, iam.NewGroup{Persona: ident.Persona("merchant"), Owner: &ownerSubject})
	require.NoError(t, err)
	token := map[string]string{"staff": unset.login(staff).AccessToken, "billing": unset.login(billing).AccessToken, "owner": unset.login(owner).AccessToken}

	t.Run("root permission on root, no configuration", func(t *testing.T) {
		read := gated(unset.auth, unset.auth.RequirePermission(customersRead))
		requireStatus(t, read(t, http.Header{}), http.StatusUnauthorized, "unauthenticated")
		require.Equal(t, staff.id, callerOf(t, read(t, bearer(token["staff"]))).Subject)
		requireStatus(t, read(t, bearer(token["billing"])), http.StatusForbidden, "forbidden")
		requireStatus(t, read(t, bearer(token["owner"])), http.StatusForbidden, "forbidden")
	})

	t.Run("persona permission without Group refuses everyone", func(t *testing.T) {
		permitted := gated(unset.auth, unset.auth.RequirePermission(refund))
		requireStatus(t, permitted(t, http.Header{}), http.StatusUnauthorized, "unauthenticated")
		for _, name := range []string{"billing", "owner", "staff"} {
			requireStatus(t, permitted(t, bearer(token[name])), http.StatusForbidden, "forbidden")
		}
	})

	t.Run("construction refuses a pattern or an unregistered permission", func(t *testing.T) {
		for _, p := range []string{"merchant:payments:void", "merchant:*", "root:*", "root:customers:*", "root:customers:delete", "customers:read"} {
			require.Panics(t, func() { unset.auth.RequirePermission(p) }, p)
		}
	})

	t.Run("with Group, root stays on root and the persona checks there", func(t *testing.T) {
		grouped := unset.replica(authtest.WithConfig(func(c *authkit.Config) { c.Merchant.Group = merchant.ID }))
		read := gated(grouped.auth, grouped.auth.RequirePermission(customersRead))
		callerOf(t, read(t, bearer(token["staff"])))
		requireStatus(t, read(t, bearer(token["owner"])), http.StatusForbidden, "forbidden")
		permitted := gated(grouped.auth, grouped.auth.RequirePermission(refund))
		callerOf(t, permitted(t, bearer(token["owner"])))
		callerOf(t, permitted(t, bearer(token["billing"])))
		requireStatus(t, permitted(t, bearer(token["staff"])), http.StatusForbidden, "forbidden")
	})

	rootGroup, err := unset.auth.Group(ctx, iam.RootGroup())
	require.NoError(t, err)
	cfg, deps, ok := builtwith.Of(unset.auth)
	require.True(t, ok)
	cfg.Merchant.Group = rootGroup.ID
	_, err = authkit.New(ctx, cfg, deps)
	require.ErrorContains(t, err, "Config.Merchant.Group is the root group")
}
