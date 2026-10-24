package critical_test

import (
	"errors"
	"net/http"
	"sync"
	"testing"

	"github.com/open-rails/authkit/auth"
	"github.com/open-rails/authkit/iam"
)

func TestCriticalSessions(t *testing.T) {
	f := newFixture(t)
	t.Run("AK-J05-C01_concurrent_refresh_has_one_successor", func(t *testing.T) {
		u := f.user(t)
		old := f.signIn(t, u)
		if old.RefreshToken == nil {
			t.Fatal("non-cookie login omitted refresh token")
		}
		body := map[string]string{"grant_type": "refresh_token", "refresh_token": *old.RefreshToken}
		responses := make([]response, 2)
		errs := make([]error, 2)
		start := make(chan struct{})
		var wg sync.WaitGroup
		for i := range responses {
			wg.Add(1)
			go func() {
				defer wg.Done()
				<-start
				responses[i], errs[i] = f.request(t.Context(), "POST", "/token", "", body)
			}()
		}
		close(start)
		wg.Wait()
		for _, err := range errs {
			noError(t, err)
		}
		one, two := tokensFrom(t, responses[0], u.ID), tokensFrom(t, responses[1], u.ID)
		if one.RefreshToken == nil || two.RefreshToken == nil || *one.RefreshToken != *two.RefreshToken || *one.RefreshToken == *old.RefreshToken {
			t.Fatal("concurrent refresh forked or failed to rotate its successor")
		}
		c1, err := f.auth.Verify(t.Context(), one.AccessToken)
		noError(t, err)
		c2, err := f.auth.Verify(t.Context(), two.AccessToken)
		noError(t, err)
		if c1.SessionID == "" || c1.SessionID != c2.SessionID {
			t.Fatal("refresh created independent session authority")
		}
		live, err := f.auth.Sessions(t.Context(), u.ID)
		noError(t, err)
		if len(live) != 1 || live[0].ID != c1.SessionID {
			t.Fatalf("refresh session state = %+v", live)
		}
		// Retrying the unacknowledged predecessor returns that same successor.
		retry := tokensFrom(t, f.call(t, "POST", "/token", "", body), u.ID)
		if retry.RefreshToken == nil || *retry.RefreshToken != *one.RefreshToken {
			t.Fatal("lost-response retry forked the rotation chain")
		}
	})
	t.Run("AK-J05-C02_revoke_other_then_all_sessions", func(t *testing.T) {
		u := f.user(t)
		one, two := f.signIn(t, u), f.signIn(t, u)
		other, err := f.auth.Verify(t.Context(), two.AccessToken)
		noError(t, err)
		f.call(t, "DELETE", "/me/sessions/"+other.SessionID, one.AccessToken, nil).want(t, http.StatusNoContent, "")
		f.call(t, "PATCH", "/me", two.AccessToken, map[string]string{"username": "revokedwriter"}).want(t, http.StatusUnauthorized, "session_revoked")
		f.call(t, "GET", "/me/sessions", one.AccessToken, nil).want(t, http.StatusOK, "")
		who := f.identity(t, one.AccessToken)
		_, err = f.auth.RevokeAccountSessions(t.Context(), who, u.ID)
		noError(t, err)
		for _, token := range []string{one.AccessToken, two.AccessToken} {
			claims, err := f.auth.Verify(t.Context(), token)
			noError(t, err)
			if !errors.Is(f.auth.CheckSession(t.Context(), claims), iam.ErrSessionRevoked) {
				t.Fatal("account revoke left a session usable")
			}
		}
		live, err := f.auth.Sessions(t.Context(), u.ID)
		noError(t, err)
		if len(live) != 0 {
			t.Fatal("revoked sessions remained in live listing")
		}
	})
	t.Run("AK-J05-C03_password_and_ban_retire_live_authority", func(t *testing.T) {
		u := f.user(t)
		current, other := f.signIn(t, u), f.signIn(t, u)
		const changed = "Changed-critical-password-2"
		f.call(t, "PUT", "/me/password", current.AccessToken, map[string]string{"new_password": changed}).want(t, http.StatusNoContent, "")
		f.call(t, "PATCH", "/me", other.AccessToken, map[string]string{"username": "oldcredential"}).want(t, http.StatusUnauthorized, "session_revoked")
		f.call(t, "POST", "/password/login", "", map[string]string{"identifier": u.Email, "password": u.Password}).want(t, http.StatusUnauthorized, "invalid_credentials")
		u.Password = changed
		newTokens := f.signIn(t, u)
		noError(t, f.auth.Ban(t.Context(), iam.SystemIdentity(), u.ID, iam.Ban{}))
		claims, err := f.auth.Verify(t.Context(), newTokens.AccessToken)
		noError(t, err)
		if !errors.Is(f.auth.CheckSession(t.Context(), claims), iam.ErrSessionRevoked) {
			t.Fatal("ban preserved live authority")
		}
		f.call(t, "POST", "/password/login", "", map[string]string{"identifier": u.Email, "password": changed}).want(t, http.StatusUnauthorized, "user_banned")
	})
	t.Run("AK-J05-C04_stateless_signature_is_not_live_session_authority", func(t *testing.T) {
		u := f.user(t)
		tokens := f.signIn(t, u)
		claims, err := f.auth.Verify(t.Context(), tokens.AccessToken)
		noError(t, err)
		if claims.UserID != u.ID || claims.SessionID == "" {
			t.Fatal("sign-in token did not bind the expected user and session")
		}
		who := f.identity(t, tokens.AccessToken)
		noError(t, f.auth.RevokeSession(t.Context(), who, u.ID, claims.SessionID))
		// An old JWT remains cryptographically valid; privileged requests must
		// nevertheless consult the now-revoked sign-in.
		_, err = f.auth.Verify(t.Context(), tokens.AccessToken)
		noError(t, err)
		if err := f.auth.CheckSession(t.Context(), claims); !errors.Is(err, iam.ErrSessionRevoked) {
			t.Fatalf("revoked session error = %v", err)
		}
		f.call(t, "PATCH", "/me", tokens.AccessToken, map[string]string{"username": "mustnotpersist"}).want(t, http.StatusUnauthorized, "session_revoked")
		r, err := http.NewRequestWithContext(t.Context(), "GET", f.server.URL+"/identity", nil)
		noError(t, err)
		r.Header.Set("Authorization", "Bearer "+tokens.AccessToken)
		if _, err = f.auth.Authenticator().Authenticate(r); !errors.Is(err, auth.ErrUnauthenticated) || !errors.Is(err, auth.ErrRevoked) {
			t.Fatalf("live authenticator must classify revoked authority: %v", err)
		}
		current, err := f.auth.User(t.Context(), iam.UserByID(u.ID))
		noError(t, err)
		if current.Username != u.Username {
			t.Fatal("refused mutation changed the public account state")
		}
	})
	t.Run("AK-J05-C05_late_refresh_cannot_undo_logout", func(t *testing.T) {
		u := f.user(t)
		session := f.signIn(t, u)
		if session.RefreshToken == nil {
			t.Fatal("missing refresh token")
		}
		f.call(t, "DELETE", "/logout", session.AccessToken, nil).want(t, http.StatusNoContent, "")
		f.call(t, "POST", "/token", "", map[string]string{"grant_type": "refresh_token", "refresh_token": *session.RefreshToken}).want(t, http.StatusUnauthorized, "invalid_token")
		f.call(t, "DELETE", "/logout", session.AccessToken, nil).want(t, http.StatusNoContent, "")
		f.call(t, "PATCH", "/me", session.AccessToken, map[string]string{"username": "latewriter"}).want(t, http.StatusUnauthorized, "session_revoked")
		fresh := f.signIn(t, u)
		oldClaims, err := f.auth.Verify(t.Context(), session.AccessToken)
		noError(t, err)
		newClaims, err := f.auth.Verify(t.Context(), fresh.AccessToken)
		noError(t, err)
		if oldClaims.SessionID == newClaims.SessionID {
			t.Fatal("fresh sign-in revived a retired session")
		}
	})
}
