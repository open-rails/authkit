package securitytest

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/open-rails/authkit"
	"github.com/open-rails/authkit/authtest"
	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/httpapi"
	"github.com/open-rails/authkit/internal/ident"
	"github.com/open-rails/authkit/internal/jose"
	"github.com/open-rails/authkit/verify"
	"github.com/stretchr/testify/require"
)

func strictRotation(c *authkit.Config) { c.Token.RefreshRotationGrace = -1 }

// TestSecurityRefreshTokenTheft replays a stolen refresh token after its
// legitimate holder rotated it. Reuse must revoke the whole session, so the
// thief cannot keep a parallel session and the victim is forced to log in.
func TestSecurityRefreshTokenTheft(t *testing.T) {
	h := newHost(t, withHTTP(generousLimits), authtest.WithConfig(strictRotation))
	for _, tc := range []struct {
		name  string
		steal func(t *testing.T, stolen, rotated string)
	}{
		{"thief replays after victim rotates", func(t *testing.T, stolen, rotated string) {
			resp := h.refresh(stolen)
			require.Equal(t, http.StatusUnauthorized, resp.status, resp.String())
			resp = h.refresh(rotated)
			require.Equal(t, http.StatusUnauthorized, resp.status, "reuse must revoke the successor: %s", resp)
		}},
		{"victim replays after thief rotates", func(t *testing.T, stolen, rotated string) {
			// Here "rotated" is the thief's successor; the victim still holds the
			// predecessor and presents it.
			resp := h.refresh(stolen)
			require.Equal(t, http.StatusUnauthorized, resp.status, resp.String())
			resp = h.refresh(rotated)
			require.Equal(t, http.StatusUnauthorized, resp.status, "the thief's successor must die with the session: %s", resp)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a := h.newAccount("theft")
			first := h.login(a)
			resp := h.refresh(first.RefreshToken)
			next := session(t, resp)
			require.NotEqual(t, first.RefreshToken, next.RefreshToken)
			tc.steal(t, first.RefreshToken, next.RefreshToken)
			// A separate login is a separate session and remains usable.
			other := h.login(a)
			require.Equal(t, http.StatusOK, h.refresh(other.RefreshToken).status)
		})
	}
}

// TestSecurityRefreshHistoryIsBounded: rotation keeps a session's retired
// tokens for 90 days. An older one is refused as unknown and leaves the session
// alone; a newer one still ends it.
func TestSecurityRefreshHistoryIsBounded(t *testing.T) {
	h := newHost(t, withHTTP(generousLimits), authtest.WithConfig(strictRotation))
	ctx := context.Background()
	a := h.newAccount("history")
	first := h.login(a)
	second := session(t, h.refresh(first.RefreshToken))
	_, err := h.pool.Exec(ctx, `UPDATE profiles.refresh_token_history h SET consumed_at = now() - interval '91 days'
 FROM profiles.refresh_sessions s WHERE s.id = h.session_id AND s.user_id = $1`, a.id)
	require.NoError(t, err)
	third := session(t, h.refresh(second.RefreshToken)) // prunes the first
	var kept int
	require.NoError(t, h.pool.QueryRow(ctx, `SELECT count(*) FROM profiles.refresh_token_history h
 JOIN profiles.refresh_sessions s ON s.id = h.session_id WHERE s.user_id = $1`, a.id).Scan(&kept))
	require.Equal(t, 1, kept, "only the second token's retirement is kept")

	require.Equal(t, http.StatusUnauthorized, h.refresh(first.RefreshToken).status)
	fourth := session(t, h.refresh(third.RefreshToken))
	require.Equal(t, http.StatusUnauthorized, h.refresh(second.RefreshToken).status)
	require.Equal(t, http.StatusUnauthorized, h.refresh(fourth.RefreshToken).status, "reuse within 90 days ends the session")
}

// TestSecurityRefreshGraceDoesNotFork proves the rotation grace window only
// re-delivers the one successor: five holders of one token refreshing at once
// (agent processes sharing a credential file) converge on one live credential
// instead of each obtaining an independent chain, and nothing is revoked.
// Two racers could be survived by minting the loser a new token; five cannot,
// since the session remembers one predecessor.
func TestSecurityRefreshGraceDoesNotFork(t *testing.T) {
	h := newHost(t, withHTTP(generousLimits))
	ctx := context.Background()
	a := h.newAccount("grace")
	first := h.login(a)
	type outcome struct {
		status int
		tokens tokens
		err    error
	}
	results := make([]outcome, 5)
	start := make(chan struct{})
	var wg sync.WaitGroup
	for i := range results {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			results[i].status, results[i].tokens, results[i].err = h.refreshFromGoroutine(first.RefreshToken)
		}()
	}
	close(start)
	wg.Wait()
	converged := results[0].tokens.RefreshToken
	for i, r := range results {
		require.NoErrorf(t, r.err, "racer %d", i)
		require.Equalf(t, http.StatusOK, r.status, "racer %d was refused", i)
		require.NotEmptyf(t, r.tokens.AccessToken, "racer %d got no access token", i)
		require.NotEqualf(t, first.RefreshToken, r.tokens.RefreshToken, "racer %d was handed back the consumed token", i)
		require.Equalf(t, converged, r.tokens.RefreshToken, "racer %d was forked onto a second credential chain", i)
	}
	sessions, err := h.auth.Sessions(ctx, a.id)
	require.NoError(t, err)
	require.Len(t, sessions, 1, "the session must survive the race")
	revoked, err := h.auth.ListSessionEvents(ctx, a.id, iam.SessionEventQuery{Kinds: []iam.SessionEventKind{iam.SessionEventRevoked}})
	require.NoError(t, err)
	require.Empty(t, revoked.Items, "a lost race must revoke nothing")

	resp := h.refresh(converged)
	next := session(t, resp)
	require.NotEqual(t, converged, next.RefreshToken, "the successor still rotates")
}

// refreshFromGoroutine is refresh reporting failures instead of failing the
// test, for racing goroutines.
func (h *host) refreshFromGoroutine(refreshToken string) (int, tokens, error) {
	body, err := json.Marshal(map[string]string{"grant_type": "refresh_token", "refresh_token": refreshToken})
	if err != nil {
		return 0, tokens{}, err
	}
	resp, err := http.Post(h.server.URL+apiPrefix+"/token", "application/json", bytes.NewReader(body))
	if err != nil {
		return 0, tokens{}, err
	}
	defer resp.Body.Close()
	var out tokens
	if resp.StatusCode == http.StatusOK {
		var res httpapi.AuthResult
		if err = json.NewDecoder(resp.Body).Decode(&res); err == nil && res.TokenSet != nil {
			out.AccessToken = res.TokenSet.AccessToken
			if res.TokenSet.RefreshToken != nil {
				out.RefreshToken = *res.TokenSet.RefreshToken
			}
		}
	}
	return resp.StatusCode, out, err
}

// TestSecuritySessionRevocationEvents proves every account-securing event ends
// previously issued refresh sessions, including on a second replica that shares
// only PostgreSQL.
func TestSecuritySessionRevocationEvents(t *testing.T) {
	h := newHost(t, withHTTP(generousLimits))
	replica := h.replica()
	ctx := context.Background()
	for _, tc := range []struct {
		name    string
		secure  func(t *testing.T, a account, session tokens)
		relogin bool // the owner can still log in with the original password
	}{
		{"logout", func(t *testing.T, _ account, s tokens) {
			resp := h.do(request{method: http.MethodDelete, path: "/logout", token: s.AccessToken})
			require.Less(t, resp.status, 300, resp.String())
		}, true},
		{"sign out every other session", func(t *testing.T, a account, _ tokens) {
			resp := h.do(request{method: http.MethodDelete, path: "/me/sessions", token: h.login(a).AccessToken})
			require.Less(t, resp.status, 300, resp.String())
		}, true},
		{"admin password reset", func(t *testing.T, a account, _ tokens) {
			require.NoError(t, h.setPassword(a.id, password))
		}, true},
		{"admin emergency revoke", func(t *testing.T, a account, _ tokens) {
			_, err := h.auth.RevokeAccountSessions(ctx, iam.SystemActor(), a.id)
			require.NoError(t, err)
		}, true},
		{"ban", func(t *testing.T, a account, _ tokens) {
			require.NoError(t, h.auth.Ban(ctx, iam.SystemActor(), a.id, iam.Ban{}))
		}, false},
		{"soft delete", func(t *testing.T, a account, _ tokens) {
			results, err := h.auth.DeleteUsers(ctx, iam.SystemActor(), []string{a.id})
			require.NoError(t, err)
			require.Len(t, results, 1)
			require.NoError(t, results[0].Err)
		}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a := h.newAccount("revoke")
			session := h.login(a)
			replicaSession := replica.login(a)
			tc.secure(t, a, session)
			require.Equal(t, http.StatusUnauthorized, h.refresh(session.RefreshToken).status)
			if tc.name != "logout" {
				require.Equal(t, http.StatusUnauthorized, replica.refresh(replicaSession.RefreshToken).status,
					"a session minted by another replica survived %s", tc.name)
			}
			login := h.post("/password/login", map[string]string{"identifier": a.email, "password": password}, "")
			if tc.relogin {
				require.Equal(t, http.StatusOK, login.status, login.String())
			} else {
				require.GreaterOrEqual(t, login.status, 400, login.String())
				require.Empty(t, login.cookies)
				require.NotContains(t, login.String(), "access_token")
			}
		})
	}
}

// TestSecurityPasswordChangeEndsOtherSessions: an attacker holding a stolen
// session loses it when the owner changes the password.
func TestSecurityPasswordChangeEndsOtherSessions(t *testing.T) {
	h := newHost(t, withHTTP(generousLimits))
	a := h.newAccount("pwchange")
	attacker := h.login(a)
	owner := h.login(a)
	resp := h.do(request{method: http.MethodPut, path: "/me/password", body: map[string]string{"new_password": "Another-long-passphrase-7"}, token: owner.AccessToken})
	require.Less(t, resp.status, 300, resp.String())
	require.Equal(t, http.StatusUnauthorized, h.refresh(attacker.RefreshToken).status)
	old := h.post("/password/login", map[string]string{"identifier": a.email, "password": password}, "")
	require.Equal(t, http.StatusUnauthorized, old.status, old.String())
}

// TestSecurityRevokedSessionCannotChangeCredentials: a stolen access token is
// still cryptographically valid after the owner logs out or secures the
// account. It must not be able to install a credential that outlives the
// revocation (new password, passkey, second factor, address) or delete the
// account.
func TestSecurityRevokedSessionCannotChangeCredentials(t *testing.T) {
	h := newHost(t, withHTTP(generousLimits), authtest.WithConfig(func(c *authkit.Config) {
		c.Passkeys = authkit.PasskeyConfig{RPID: "localhost", RPDisplayName: "Security", Origins: []string{"http://localhost"}}
	}))
	ctx := context.Background()
	attacks := []struct {
		name string
		req  func(token string) request
	}{
		{"set a password", func(token string) request {
			return request{method: http.MethodPut, path: "/me/password", token: token, body: map[string]string{"new_password": "Attacker-owned-passphrase-1"}}
		}},
		{"register a passkey", func(token string) request {
			return request{method: http.MethodPost, path: "/me/passkeys/register/begin", token: token}
		}},
		{"enroll a second factor", func(token string) request {
			return request{method: http.MethodPost, path: "/me/2fa/setup", token: token, body: map[string]string{"method": "email"}}
		}},
		{"delete the account", func(token string) request {
			return request{method: http.MethodDelete, path: "/me", token: token}
		}},
		{"change the address", func(token string) request {
			return request{method: http.MethodPut, path: "/me/email", token: token, body: map[string]string{"email": unique("attacker") + "@security.test"}}
		}},
	}
	events := []struct {
		name   string
		revoke func(t *testing.T, a account, stolen tokens)
	}{
		{"owner logs out the stolen session", func(t *testing.T, _ account, stolen tokens) {
			require.Less(t, h.do(request{method: http.MethodDelete, path: "/logout", token: stolen.AccessToken}).status, 300)
		}},
		{"owner revokes all sessions", func(t *testing.T, a account, _ tokens) {
			own := h.login(a)
			require.Less(t, h.do(request{method: http.MethodDelete, path: "/me/sessions", token: own.AccessToken}).status, 300)
		}},
		{"owner changes password", func(t *testing.T, a account, _ tokens) {
			own := h.login(a)
			resp := h.do(request{method: http.MethodPut, path: "/me/password", body: map[string]string{"new_password": password + "x"}, token: own.AccessToken})
			require.Less(t, resp.status, 300, resp.String())
			require.NoError(t, h.setPassword(a.id, password))
		}},
		{"the system bans the account", func(t *testing.T, a account, _ tokens) {
			require.NoError(t, h.auth.Ban(ctx, iam.SystemActor(), a.id, iam.Ban{}))
		}},
	}
	for _, event := range events {
		for _, attack := range attacks {
			t.Run(event.name+"/"+attack.name, func(t *testing.T) {
				a := h.newAccount("stolen")
				stolen := h.login(a)
				event.revoke(t, a, stolen)
				resp := h.do(attack.req(stolen.AccessToken))
				require.Contains(t, []int{http.StatusUnauthorized, http.StatusForbidden}, resp.status, resp.String())
				u, err := h.auth.User(ctx, iam.UserByID(a.id), authkit.IncludeDeleted())
				require.NoError(t, err)
				require.Nil(t, u.DeletedAt)
				if event.name != "the system bans the account" {
					login := h.post("/password/login", map[string]string{"identifier": a.email, "password": "Attacker-owned-passphrase-1"}, "")
					require.Equal(t, http.StatusUnauthorized, login.status, login.String())
				}
			})
		}
	}
	t.Run("control: a live fresh session may use every route", func(t *testing.T) {
		for _, attack := range attacks[:3] {
			a := h.newAccount("live")
			resp := h.do(attack.req(h.login(a).AccessToken))
			require.Less(t, resp.status, 300, "%s: %s", attack.name, resp)
		}
	})
}

func delegateCertificate(t *testing.T) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	now := time.Now()
	der, err := x509.CreateCertificate(rand.Reader, &x509.Certificate{
		SerialNumber: big.NewInt(now.UnixNano()),
		Subject:      pkix.Name{CommonName: "delegate"},
		NotBefore:    now.Add(-time.Minute),
		NotAfter:     now.Add(2 * time.Hour),
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}, &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "delegate"}}, &key.PublicKey, key)
	require.NoError(t, err)
	return base64.RawURLEncoding.EncodeToString(der)
}

// TestSecurityDelegationOutlivingRevocation: a delegated token lives longer
// than its parent access token, so minting one from a revoked session or a
// banned account would extend a thief's access past revocation.
func TestSecurityDelegationOutlivingRevocation(t *testing.T) {
	h := newHost(t, withHTTP(generousLimits), authtest.WithConfig(func(c *authkit.Config) {
		c.Delegated = authkit.DelegatedConfig{Audiences: []string{"resource.security.test"}}
	}), authtest.WithDeps(func(d *authkit.Deps) {
		d.DelegatedAuthorization = func(context.Context, iam.DelegationRequest) (iam.DelegationGrant, error) {
			return iam.DelegationGrant{Permissions: []string{"resource:read"}}, nil
		}
	}))
	ctx := context.Background()
	mint := func(token string) response {
		return h.post("/delegated/token", map[string]any{
			"delegate_certificate_der_b64url": delegateCertificate(t),
			"requested_grant":                 map[string]any{"scope": "read"},
		}, token)
	}
	for _, tc := range []struct {
		name   string
		revoke func(a account, s tokens)
	}{
		{"after logout", func(_ account, s tokens) {
			require.Less(t, h.do(request{method: http.MethodDelete, path: "/logout", token: s.AccessToken}).status, 300)
		}},
		{"after ban", func(a account, _ tokens) { require.NoError(t, h.auth.Ban(ctx, iam.SystemActor(), a.id, iam.Ban{})) }},
		{"after soft delete", func(a account, _ tokens) {
			_, err := h.auth.DeleteUsers(ctx, iam.SystemActor(), []string{a.id})
			require.NoError(t, err)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a := h.newAccount("delegate")
			s := h.login(a)
			tc.revoke(a, s)
			resp := mint(s.AccessToken)
			require.Equal(t, http.StatusUnauthorized, resp.status, resp.String())
		})
	}
	t.Run("control: live session mints", func(t *testing.T) {
		resp := mint(h.login(h.newAccount("delegatelive")).AccessToken)
		require.Equal(t, http.StatusOK, resp.status, resp.String())
	})
}

// TestSecurityDelegatedGrantClamp: delegated permissions are scope-free, so a
// grant may carry AuthKit authority only when the user holds it at the root,
// and a token this deployment minted loses that authority when the user does.
func TestSecurityDelegatedGrantClamp(t *testing.T) {
	var mu sync.Mutex
	var grant []string
	h := newHost(t, withHTTP(generousLimits), authtest.WithConfig(withRBAC), authtest.WithConfig(func(c *authkit.Config) {
		c.Delegated = authkit.DelegatedConfig{Audiences: []string{"resource.security.test"}}
	}), authtest.WithDeps(func(d *authkit.Deps) {
		d.DelegatedAuthorization = func(context.Context, iam.DelegationRequest) (iam.DelegationGrant, error) {
			mu.Lock()
			defer mu.Unlock()
			return iam.DelegationGrant{Permissions: append([]string(nil), grant...)}, nil
		}
	}))
	ctx := context.Background()
	manager, moderator := h.newAccount("delegmanager"), h.newAccount("delegmod")
	group, _ := h.newOrg(h.newAccount("delegowner"))
	h.grant(group, manager, "manager")
	h.grant(iam.RootGroup(), moderator, "moderator")
	mint := func(a account, perms ...string) response {
		mu.Lock()
		grant = perms
		mu.Unlock()
		return h.post("/delegated/token", map[string]any{
			"delegate_certificate_der_b64url": delegateCertificate(t),
			"requested_grant":                 map[string]any{"scope": "clamp"},
		}, h.login(a).AccessToken)
	}
	for _, tc := range []struct {
		name  string
		who   account
		perms []string
	}{
		{"group role as scope-free authority", manager, []string{"org:members:manage"}},
		{"root authority the user lacks", manager, []string{ident.RootUsersBan.String()}},
		{"wildcard", moderator, []string{"*"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resp := mint(tc.who, tc.perms...)
			require.Equal(t, http.StatusForbidden, resp.status, resp.String())
			require.Equal(t, "delegation_refused", resp.errorCode())
		})
	}
	t.Run("control: host vocabulary and held root authority", func(t *testing.T) {
		resp := mint(manager, "resource:read")
		require.Equal(t, http.StatusOK, resp.status, resp.String())
		resp = mint(moderator, ident.RootUsersBan.String(), "resource:read")
		require.Equal(t, http.StatusOK, resp.status, resp.String())
	})
	t.Run("a minted token loses authority its user lost", func(t *testing.T) {
		perm := iam.Perm(ident.RootUsersBan)
		cl := verify.Claims{Kind: iam.ActorDelegated, Issuer: issuer, DelegatedSubject: moderator.id, JOSEType: jose.DelegatedAccessTokenType, Permissions: []string{perm.String()}}
		ok, err := allow(ctx, h.auth, cl, perm, iam.RootGroup())
		require.NoError(t, err)
		require.True(t, ok)
		revokeRole(t, h.auth, iam.RootGroup(), iam.UserSubject(moderator.id), "moderator")
		ok, err = allow(ctx, h.auth, cl, perm, iam.RootGroup())
		require.NoError(t, err)
		require.False(t, ok, "a delegated token kept root authority its user lost")
	})
}
