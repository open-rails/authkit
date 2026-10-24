package critical_test

import (
	"errors"
	"net/http"
	"testing"

	"github.com/open-rails/authkit/auth"
	"github.com/open-rails/authkit/iam"
)

func TestCriticalSessions(t *testing.T) {
	f := newFixture(t)
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
}
