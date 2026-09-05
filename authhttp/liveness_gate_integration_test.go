package authhttp

import (
	"context"
	"crypto"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	authkit "github.com/open-rails/authkit"
	authcore "github.com/open-rails/authkit/internal/authcore"
	"github.com/open-rails/authkit/jwtkit"
	"github.com/open-rails/authkit/verify"
	"github.com/stretchr/testify/require"
)

// #267 end-to-end: a REAL Postgres-backed engine, a REAL verifier wired to its
// own signing keys, a REAL http.Server, and REAL minted access tokens driven
// over the wire. The gate under test is the one a host mounts — no fakes stand
// in for the engine, the token, or the transport.

func newLivenessTestEngine(t *testing.T, pool *pgxpool.Pool, issuer string) (*authcore.Service, *verify.Verifier) {
	t.Helper()
	signer, err := jwtkit.NewRSASigner(2048, "liveness-kid")
	require.NoError(t, err)
	svc, err := authcore.NewFromConfig(authcore.Config{
		Token: authcore.TokenConfig{
			Issuer:              issuer,
			IssuedAudiences:     []string{"test-app"},
			ExpectedAudiences:   []string{"test-app"},
			AccessTokenDuration: time.Hour,
		},
		Registration: authcore.RegistrationConfig{Verification: authcore.RegistrationVerificationNone},
		Keys: authcore.KeysConfig{Source: jwtkit.StaticKeySource{
			Active: signer,
			Pubs:   map[string]crypto.PublicKey{"liveness-kid": signer.PublicKey()},
		}},
		RBAC: []authcore.PersonaDef{authcore.IntrinsicRootPersona(authcore.RoleDef{Name: "no-access"})},
	}, pool)
	require.NoError(t, err)
	require.NoError(t, svc.SeedPermissionGroupContainment(context.Background()))
	_, err = svc.EnsureRootGroup(context.Background())
	require.NoError(t, err)

	ver := verify.NewVerifier(verify.WithSkew(5 * time.Second))
	require.NoError(t, ver.AddIssuer(issuer, []string{"test-app"}, verify.IssuerOptions{
		RawKeys: svc.PublicKeysByKID(),
		IsLocal: true,
	}))
	ver.WithService(svc)
	return svc, ver
}

// echoClaimsHandler is the protected resource: it reports the claims the gate
// handed downstream, which is how the freshness assertion is made against a real
// response body rather than an in-process value.
func echoClaimsHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cl, err := verify.GetClaims(r.Context())
		if err != nil {
			http.Error(w, "no claims", http.StatusInternalServerError)
			return
		}
		fmt.Fprintf(w, "%s|%s|%t", cl.UserID, cl.Username, cl.EmailVerified)
	})
}

func getWithToken(t *testing.T, url, token string) (int, string) {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, url, nil)
	require.NoError(t, err)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	return resp.StatusCode, string(body)
}

func TestRequiredLive_GateAndFreshness_DB(t *testing.T) {
	pool := newServerTestPool(t) // skips when AUTHKIT_TEST_DATABASE_URL unset
	ctx := context.Background()
	svc, ver := newLivenessTestEngine(t, pool, "https://liveness-gate.example.com")
	ver.WithLiveness(svc)

	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	mk := func(tag string) (string, string) {
		u, err := svc.CreateUser(ctx, "gate"+tag+suffix+"@example.com", "gate"+tag+suffix)
		require.NoError(t, err)
		tok, _, err := svc.MintAccessToken(ctx, u.ID, nil)
		require.NoError(t, err)
		return u.ID, tok
	}
	liveID, liveTok := mk("live")
	bannedID, bannedTok := mk("ban")
	deletedID, deletedTok := mk("del")

	live := httptest.NewServer(verify.RequiredLive(ver)(echoClaimsHandler()))
	t.Cleanup(live.Close)
	stateless := httptest.NewServer(verify.Required(ver)(echoClaimsHandler()))
	t.Cleanup(stateless.Close)

	t.Run("live user passes", func(t *testing.T) {
		code, body := getWithToken(t, live.URL, liveTok)
		require.Equal(t, http.StatusOK, code, body)
		require.Equal(t, liveID+"|gatelive"+suffix+"|false", body)
	})

	t.Run("no token is still 401", func(t *testing.T) {
		code, _ := getWithToken(t, live.URL, "")
		require.Equal(t, http.StatusUnauthorized, code)
	})

	t.Run("claims are fresh, not token-minted", func(t *testing.T) {
		// Rename and verify the email AFTER the token was minted. The token still
		// carries the old values; the gate must hand the handler the new ones.
		renamed := "renamed" + suffix
		require.NoError(t, svc.UpdateUsername(ctx, liveID, renamed))
		require.NoError(t, svc.SetEmailVerified(ctx, liveID, true))

		code, body := getWithToken(t, live.URL, liveTok)
		require.Equal(t, http.StatusOK, code, body)
		require.Equal(t, liveID+"|"+renamed+"|true", body,
			"RequiredLive must enrich from the live record — this is what replaces a per-request AdminGetUser")

		// The stateless gate, unchanged, reports only what the token itself
		// carries — which for username is NOTHING. That empty field is the whole
		// reason a host reached for an admin read per request.
		code, body = getWithToken(t, stateless.URL, liveTok)
		require.Equal(t, http.StatusOK, code)
		require.Equal(t, liveID+"||false", body,
			"the stateless path must stay stateless — it is an explicit opt-out, not a deprecated one")
	})

	t.Run("banned user is rejected on the next request", func(t *testing.T) {
		reason := "spam"
		require.NoError(t, svc.BanUser(ctx, bannedID, &reason, nil, liveID))

		code, _ := getWithToken(t, live.URL, bannedTok)
		require.Equal(t, http.StatusUnauthorized, code)

		// Same still-valid token sails through the stateless gate — the residual
		// #90 window this feature exists to close.
		code, _ = getWithToken(t, stateless.URL, bannedTok)
		require.Equal(t, http.StatusOK, code)
	})

	t.Run("soft-deleted user is rejected", func(t *testing.T) {
		_, err := svc.SoftDeleteUsers(ctx, []string{deletedID})
		require.NoError(t, err)

		code, _ := getWithToken(t, live.URL, deletedTok)
		require.Equal(t, http.StatusUnauthorized, code)
	})
}

// errLiveness injects a directory outage. It is fault injection on a dependency,
// not a stand-in for the system under test: everything else in this test is the
// real engine.
type errLiveness struct{}

func (errLiveness) UserLivenessByIDs(context.Context, []string) (map[string]authkit.UserLiveness, error) {
	return nil, errors.New("directory unavailable")
}

func TestRequiredLive_FailsClosedOnLookupError_DB(t *testing.T) {
	pool := newServerTestPool(t)
	ctx := context.Background()
	svc, ver := newLivenessTestEngine(t, pool, "https://liveness-failclosed.example.com")

	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	u, err := svc.CreateUser(ctx, "closed"+suffix+"@example.com", "closed"+suffix)
	require.NoError(t, err)
	tok, _, err := svc.MintAccessToken(ctx, u.ID, nil)
	require.NoError(t, err)

	ver.WithLiveness(errLiveness{})
	ts := httptest.NewServer(verify.RequiredLive(ver)(echoClaimsHandler()))
	t.Cleanup(ts.Close)

	code, body := getWithToken(t, ts.URL, tok)
	require.Equal(t, http.StatusUnauthorized, code,
		"a liveness lookup failure must deny — a gate that opens when its dependency is down is not a gate")
	require.NotContains(t, body, u.ID)
}

// A gate that cannot perform its check must refuse at MOUNT, loudly, rather than
// sit in the route table looking like protection it cannot provide.
func TestRequiredLive_RefusesToMountWithoutLivenessSource(t *testing.T) {
	v := verify.NewVerifier()
	require.False(t, v.HasLiveness())
	require.Panics(t, func() { verify.RequiredLive(v)(echoClaimsHandler()) })
	require.Panics(t, func() { verify.RequiredLiveUser(v)(echoClaimsHandler()) })

	// And the out-of-band caller gets a typed configuration error, never a 401 —
	// a misconfigured host must not look like a deployment where everyone is banned.
	_, err := v.VerifyRequestLive(httptest.NewRequest(http.MethodGet, "/", nil))
	require.ErrorIs(t, err, verify.ErrLivenessUnconfigured)
}

// #267's composition requirement: "live AND permitted" is one library call, so a
// host cannot get the two gates out of order or ship only half of them.
func TestAllowLive_DeniesBannedUserWhoStillHoldsThePermission_DB(t *testing.T) {
	pool := newServerTestPool(t)
	ctx := context.Background()
	svc, ver := newLivenessTestEngine(t, pool, "https://allowlive.example.com")
	ver.WithLiveness(svc)

	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	u, err := svc.CreateUser(ctx, "al"+suffix+"@example.com", "al"+suffix)
	require.NoError(t, err)
	require.NoError(t, svc.AssignGroupRoleGenesis(ctx, "root", "", u.ID, "user", "owner"))

	tok, _, err := svc.MintAccessToken(ctx, u.ID, nil)
	require.NoError(t, err)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	cl, err := ver.VerifyRequest(req)
	require.NoError(t, err)

	group, err := svc.GroupInstanceForSlug(ctx, "root", "")
	require.NoError(t, err)
	scope := verify.PermissionScope{GroupID: group.ID, AuthorityIssuer: svc.Config().Token.Issuer, Persona: "root"}
	perms, err := svc.ListEffectivePermissions(ctx, u.ID, "user", "root", "")
	require.NoError(t, err)
	require.NotEmpty(t, perms, "fixture must grant at least one permission for the denial to mean anything")
	perm := perms[0]

	allowed, err := ver.AllowLive(ctx, svc, cl, perm, scope)
	require.NoError(t, err)
	require.True(t, allowed, "a live owner holds its own effective permission")

	reason := "spam"
	require.NoError(t, svc.BanUser(ctx, u.ID, &reason, nil, u.ID))

	stillPermitted, err := verify.Allow(ctx, svc, cl, perm, scope)
	require.NoError(t, err)
	require.True(t, stillPermitted, "the permission assignment itself survives a ban — which is exactly the trap")

	allowed, err = ver.AllowLive(ctx, svc, cl, perm, scope)
	require.NoError(t, err)
	require.False(t, allowed, "AllowLive must deny a banned account that still holds the permission")
}
