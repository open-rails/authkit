package critical_test

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/open-rails/authkit/authtest"
	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/testclock"
)

func TestCriticalFreshAuthority(t *testing.T) {
	t.Run("AK-J08-C01_freshness_has_an_exact_boundary", func(t *testing.T) {
		f := newFixture(t)
		var fixed atomic.Pointer[time.Time]
		// The existing clock seam controls only time. Services, sessions,
		// authorization and persistence remain the real implementation.
		testclock.Use(f.auth, func() time.Time {
			if at := fixed.Load(); at != nil {
				return *at
			}
			return time.Now()
		})
		u := f.user(t)
		session := f.signIn(t, u)
		claims, err := f.auth.Verify(t.Context(), session.AccessToken)
		noError(t, err)
		noError(t, f.auth.CheckRecentSignIn(t.Context(), claims))
		boundary := claims.AuthTime.Add(15 * time.Minute)
		fixed.Store(&boundary)
		noError(t, f.auth.CheckRecentSignIn(t.Context(), claims))
		late := boundary.Add(time.Second)
		fixed.Store(&late)
		if e, ok := iam.AsError(f.auth.CheckRecentSignIn(t.Context(), claims)); !ok || e.Code() != "step_up_required" {
			t.Fatalf("stale sign-in was not refused: %v", e)
		}
		fixed.Store(nil)
		stale := authtest.StaleSession(t, f.auth, session.AccessToken)
		r := f.call(t, "PUT", "/me/password", stale, map[string]string{"new_password": "Must-not-set-stale-password-9"})
		r.want(t, http.StatusUnauthorized, "step_up_required")
		if !strings.Contains(r.header.Get("WWW-Authenticate"), "insufficient_user_authentication") {
			t.Fatal("freshness refusal omitted its challenge")
		}
		f.signIn(t, u)
	})
	t.Run("AK-J08-C02_native_step_up_cannot_substitute_for_enrolled_MFA", func(t *testing.T) {
		f := newFixture(t)
		u := f.user(t)
		session := f.signIn(t, u)
		stale := authtest.StaleSession(t, f.auth, session.AccessToken)
		f.call(t, "POST", "/me/step-up/password", stale, map[string]string{"password": "wrong-password"}).want(t, http.StatusUnauthorized, "invalid_password")
		fresh := tokensFrom(t, f.call(t, "POST", "/me/step-up/password", stale, map[string]string{"password": u.Password}), u.ID)
		claims, err := f.auth.Verify(t.Context(), fresh.AccessToken)
		noError(t, err)
		noError(t, f.auth.CheckRecentSignIn(t.Context(), claims))
		stale = authtest.StaleSession(t, f.auth, fresh.AccessToken)
		f.call(t, "POST", "/me/step-up/code/send", stale, map[string]string{"channel": "email"}).want(t, http.StatusAccepted, "")
		code := f.out.Last(t, iam.MessageLoginCode, u.Email).Code
		tokensFrom(t, f.call(t, "POST", "/me/step-up/code", stale, map[string]string{"code": code}), u.ID)
		m := mfaFixture(t, iam.TwoFactorOptional)
		user := m.user(t)
		secret, created := m.totp(t, m.signIn(t, user).AccessToken)
		qualified := factorSession(t, created, user.ID)
		old := authtest.StaleSession(t, m.auth, qualified.AccessToken)
		m.call(t, "POST", "/me/step-up/password", old, map[string]string{"password": user.Password}).want(t, http.StatusUnauthorized, "step_up_required")
		m.call(t, "POST", "/me/step-up/code/send", old, map[string]string{"channel": "email"}).want(t, http.StatusUnauthorized, "step_up_required")
		m.call(t, "POST", "/me/step-up/2fa/send", old, map[string]string{"factor_id": created.Factor.ID}).want(t, http.StatusAccepted, "")
		tokensFrom(t, m.call(t, "POST", "/me/step-up/2fa", old, map[string]string{"factor_id": created.Factor.ID, "code": authtest.TOTPCode(t, secret, time.Now().Add(30*time.Second))}), user.ID)
	})
	t.Run("AK-J08-C03_contact_step_up_is_session_bound_and_single_use", func(t *testing.T) {
		f := newFixture(t)
		u := f.user(t)
		one, two := f.signIn(t, u), f.signIn(t, u)
		one.AccessToken = authtest.StaleSession(t, f.auth, one.AccessToken)
		two.AccessToken = authtest.StaleSession(t, f.auth, two.AccessToken)
		f.call(t, "POST", "/me/step-up/code/send", one.AccessToken, map[string]string{"channel": "email"}).want(t, http.StatusAccepted, "")
		code := f.out.Last(t, iam.MessageLoginCode, u.Email).Code
		f.call(t, "POST", "/me/step-up/code", two.AccessToken, map[string]string{"code": code}).want(t, http.StatusUnauthorized, "code_expired")
		other := f.user(t)
		otherToken := f.signIn(t, other)
		f.call(t, "POST", "/me/step-up/code", otherToken.AccessToken, map[string]string{"code": code}).want(t, http.StatusUnauthorized, "code_expired")
		tokensFrom(t, f.call(t, "POST", "/me/step-up/code", one.AccessToken, map[string]string{"code": code}), u.ID)
		f.call(t, "POST", "/me/step-up/code", one.AccessToken, map[string]string{"code": code}).want(t, http.StatusUnauthorized, "code_expired")
	})
	t.Run("AK-J08-C04_late_or_cancelled_operations_do_not_gain_authority", func(t *testing.T) {
		f := newFixture(t)
		u := f.user(t)
		token := f.signIn(t, u)
		stale := authtest.StaleSession(t, f.auth, token.AccessToken)
		f.call(t, "POST", "/me/step-up/code/send", stale, map[string]string{"channel": "email"}).want(t, http.StatusAccepted, "")
		code := f.out.Last(t, iam.MessageLoginCode, u.Email).Code
		f.call(t, "DELETE", "/logout", stale, nil).want(t, http.StatusNoContent, "")
		f.call(t, "POST", "/me/step-up/code", stale, map[string]string{"code": code}).want(t, http.StatusUnauthorized, "session_revoked")
		live := f.signIn(t, u)
		who := f.identity(t, live.AccessToken)
		ctx, cancel := context.WithCancel(t.Context())
		cancel()
		name := "cancelledmutation"
		_, err := f.auth.UpdateUser(ctx, who, u.ID, iam.UserUpdate{Username: &name})
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("cancelled public mutation returned %v", err)
		}
		got, err := f.auth.User(t.Context(), iam.UserByID(u.ID))
		noError(t, err)
		if got.Username != u.Username {
			t.Fatal("cancelled-before-acceptance mutation committed")
		}
		other := f.user(t)
		f.call(t, "PUT", "/admin/users/"+other.ID+"/ban", live.AccessToken, map[string]string{"reason": "not permitted"}).want(t, http.StatusForbidden, "insufficient_authority")
	})
	t.Run("AK-J08-C05_machine_or_host_minted_identity_is_not_recent_sign_in", func(t *testing.T) {
		f := newFixture(t)
		key, _, who := f.key(t)
		claims, err := f.auth.Verify(t.Context(), key.Secret)
		noError(t, err)
		if e, ok := iam.AsError(f.auth.CheckRecentSignIn(t.Context(), claims)); !ok || e.Status() != http.StatusForbidden {
			t.Fatalf("machine acquired freshness: %v", e)
		}
		f.call(t, "POST", "/me/step-up/password", key.Secret, map[string]string{"password": authtest.Password}).want(t, http.StatusForbidden, "forbidden")
		token, err := f.auth.MintAccessToken(t.Context(), who.Subject, iam.AccessTokenOptions{})
		noError(t, err)
		cl, err := f.auth.Verify(t.Context(), token.Value)
		noError(t, err)
		if err := f.auth.CheckRecentSignIn(t.Context(), cl); err == nil {
			t.Fatal("host-minted identity fabricated an interactive sign-in")
		}
		_, err = f.auth.MintAccessToken(t.Context(), who.Subject, iam.AccessTokenOptions{Claims: map[string]any{"auth_time": time.Now().Unix()}})
		if e, ok := iam.AsError(err); !ok || e.Code() != "invalid_request" {
			t.Fatalf("reserved freshness claim override accepted: %v", err)
		}
	})
}
