package securitytest

import (
	"context"
	"net/http"
	"testing"

	"github.com/open-rails/authkit/embedded"
	"github.com/stretchr/testify/require"
)

func strictRotation(c *embedded.Config) { c.Token.RefreshRotationGrace = -1 }

// TestSecurityRefreshTokenTheft replays a stolen refresh token after its
// legitimate holder rotated it. Reuse must revoke the whole family, so the
// thief cannot keep a parallel session and the victim is forced to log in.
func TestSecurityRefreshTokenTheft(t *testing.T) {
	h := newHost(t, withHTTP(generousLimits), withEngine(strictRotation))
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
			require.Equal(t, http.StatusUnauthorized, resp.status, "the thief's successor must die with the family: %s", resp)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a := h.newAccount("theft")
			first := h.login(a)
			resp := h.refresh(first.RefreshToken)
			require.Equal(t, http.StatusOK, resp.status, resp.String())
			var next tokens
			resp.json(t, &next)
			require.NotEqual(t, first.RefreshToken, next.RefreshToken)
			tc.steal(t, first.RefreshToken, next.RefreshToken)
			// A separate login is a separate family and remains usable.
			other := h.login(a)
			require.Equal(t, http.StatusOK, h.refresh(other.RefreshToken).status)
		})
	}
}

// TestSecurityRefreshGraceDoesNotFork proves the rotation grace window only
// re-delivers the one successor: concurrent holders converge instead of each
// obtaining an independent credential chain.
func TestSecurityRefreshGraceDoesNotFork(t *testing.T) {
	h := newHost(t, withHTTP(generousLimits))
	a := h.newAccount("grace")
	first := h.login(a)
	var got [2]tokens
	for i := range got {
		resp := h.refresh(first.RefreshToken)
		require.Equal(t, http.StatusOK, resp.status, resp.String())
		resp.json(t, &got[i])
	}
	require.Equal(t, got[0].RefreshToken, got[1].RefreshToken, "a replay inside the grace window forked the session")
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
		{"revoke all sessions", func(t *testing.T, _ account, s tokens) {
			resp := h.do(request{method: http.MethodDelete, path: "/user/sessions", token: s.AccessToken})
			require.Less(t, resp.status, 300, resp.String())
		}, true},
		{"admin password reset", func(t *testing.T, a account, _ tokens) {
			require.NoError(t, h.client.AdminSetPassword(ctx, a.id, password))
		}, true},
		{"admin emergency revoke", func(t *testing.T, a account, _ tokens) {
			_, err := h.client.AdminRevokeAccountSessions(ctx, a.id)
			require.NoError(t, err)
		}, true},
		{"ban", func(t *testing.T, a account, _ tokens) {
			require.NoError(t, h.client.BanUser(ctx, a.id, nil, nil, a.id))
		}, false},
		{"soft delete", func(t *testing.T, a account, _ tokens) {
			results, err := h.client.SoftDeleteUsers(ctx, []string{a.id})
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
	resp := h.post("/user/password", map[string]string{"current_password": password, "new_password": "Another-long-passphrase-7"}, owner.AccessToken)
	require.Less(t, resp.status, 300, resp.String())
	require.Equal(t, http.StatusUnauthorized, h.refresh(attacker.RefreshToken).status)
	old := h.post("/password/login", map[string]string{"identifier": a.email, "password": password}, "")
	require.Equal(t, http.StatusUnauthorized, old.status, old.String())
}

// replica builds a second runtime over the same database, as a multi-replica
// host deployment does.
func (h *host) replica() *host {
	h.t.Helper()
	r, err := embedded.New(h.cfg.engine, h.cfg.deps)
	require.NoError(h.t, err)
	h.t.Cleanup(r.Close)
	return h.fork(r)
}

// TestSecurityRevokedSessionCannotChangeCredentials: a stolen access token is
// still cryptographically valid after the owner logs out or secures the
// account. It must not be able to install a credential that outlives the
// revocation (new password, passkey, second factor) or delete the account.
func TestSecurityRevokedSessionCannotChangeCredentials(t *testing.T) {
	h := newHost(t, withHTTP(generousLimits), withEngine(func(c *embedded.Config) {
		c.Passkeys = embedded.PasskeyConfig{RPID: "localhost", RPDisplayName: "Security", Origins: []string{"http://localhost"}}
	}))
	ctx := context.Background()
	attacks := []struct {
		name string
		req  func(token string) request
	}{
		{"set password without current password", func(token string) request {
			return request{method: http.MethodPost, path: "/user/password", token: token, body: map[string]string{"new_password": "Attacker-owned-passphrase-1"}}
		}},
		{"register a passkey", func(token string) request {
			return request{method: http.MethodPost, path: "/passkeys/register/begin", token: token, body: map[string]any{}}
		}},
		{"enroll a second factor", func(token string) request {
			return request{method: http.MethodPost, path: "/user/2fa", token: token, body: map[string]string{"method": "email"}}
		}},
		{"delete the account", func(token string) request {
			return request{method: http.MethodDelete, path: "/user", token: token, body: map[string]any{}}
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
			require.Less(t, h.do(request{method: http.MethodDelete, path: "/user/sessions", token: own.AccessToken}).status, 300)
		}},
		{"owner changes password", func(t *testing.T, a account, _ tokens) {
			own := h.login(a)
			resp := h.post("/user/password", map[string]string{"current_password": password, "new_password": password + "x"}, own.AccessToken)
			require.Less(t, resp.status, 300, resp.String())
			require.NoError(t, h.client.AdminSetPassword(ctx, a.id, password))
		}},
		{"operator bans the account", func(t *testing.T, a account, _ tokens) {
			require.NoError(t, h.client.BanUser(ctx, a.id, nil, nil, a.id))
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
				u, err := h.client.AdminGetUser(ctx, a.id)
				require.NoError(t, err)
				require.Nil(t, u.DeletedAt)
				if event.name != "operator bans the account" {
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
