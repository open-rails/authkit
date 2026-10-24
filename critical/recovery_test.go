package critical_test

import (
	"context"
	"errors"
	"net/http"
	"sync"
	"testing"

	"github.com/open-rails/authkit/authtest"
	"github.com/open-rails/authkit/iam"
)

func (f *fixture) resetProof(t *testing.T, address string) string {
	t.Helper()
	f.call(t, "POST", "/password/reset/request", "", map[string]string{"identifier": address}).want(t, http.StatusAccepted, "")
	token := f.out.Last(t, iam.MessagePasswordReset, address).Token
	if token == "" {
		t.Fatal("password recovery did not deliver a reset token")
	}
	return token
}

func TestCriticalRecovery(t *testing.T) {
	f := newFixture(t)
	t.Run("AK-J06-C01_email_and_sms_reset_preserve_admission_gates", func(t *testing.T) {
		u := f.user(t)
		old := f.signIn(t, u)
		proof := f.resetProof(t, u.Email)
		const changed = "Reset-critical-password-3"
		f.call(t, "POST", "/password/reset/confirm", "", map[string]string{"token": proof, "new_password": changed}).want(t, http.StatusNoContent, "")
		f.call(t, "PATCH", "/me", old.AccessToken, map[string]string{"username": "resetold"}).want(t, http.StatusUnauthorized, "session_revoked")
		f.call(t, "POST", "/password/login", "", map[string]string{"identifier": u.Email, "password": u.Password}).want(t, http.StatusUnauthorized, "invalid_credentials")
		u.Password = changed
		f.signIn(t, u)
		phone := "+12025550177"
		p, err := f.auth.CreateUser(t.Context(), iam.NewUser{Phone: phone, PhoneVerified: true, Username: "smsresetperson", Password: authtest.Password})
		noError(t, err)
		proof = f.resetProof(t, phone)
		f.call(t, "POST", "/password/reset/confirm", "", map[string]string{"token": proof, "new_password": changed}).want(t, http.StatusNoContent, "")
		f.call(t, "POST", "/password/login", "", map[string]string{"identifier": phone, "password": authtest.Password}).want(t, http.StatusUnauthorized, "invalid_credentials")
		r := f.call(t, "POST", "/password/login", "", map[string]string{"identifier": phone, "password": changed})
		r.want(t, http.StatusOK, "")
		var answer struct {
			Status string        `json:"status"`
			Tokens *iam.TokenSet `json:"token_set"`
			Device struct {
				UserID string `json:"user_id"`
			} `json:"device_verification"`
		}
		decode(t, r.body, &answer)
		if answer.Status != "device_verification_required" || answer.Tokens != nil || answer.Device.UserID != p.ID {
			t.Fatalf("phone reset bypassed new-device proof: %s", r.body)
		}
	})
	t.Run("AK-J06-C02_invalid_expired_and_used_reset_proofs_fail", func(t *testing.T) {
		g := newFixture(t)
		u := g.user(t)
		const changed = "Single-use-reset-password-4"
		g.call(t, "POST", "/password/reset/confirm", "", map[string]string{"token": "not-a-reset-proof", "new_password": changed}).want(t, http.StatusBadRequest, "invalid_link")
		expired := g.resetProof(t, u.Email)
		g.expireProofs(t)
		g.call(t, "POST", "/password/reset/confirm", "", map[string]string{"token": expired, "new_password": changed}).want(t, http.StatusBadRequest, "invalid_link")
		g.signIn(t, u)
		valid := g.resetProof(t, u.Email)
		g.call(t, "POST", "/password/reset/confirm", "", map[string]string{"token": valid, "new_password": changed}).want(t, http.StatusNoContent, "")
		g.call(t, "POST", "/password/reset/confirm", "", map[string]string{"token": valid, "new_password": "Must-not-replace-password-5"}).want(t, http.StatusBadRequest, "invalid_link")
		u.Password = changed
		g.signIn(t, u)
	})
	t.Run("AK-J06-C03_contact_changes_require_the_new_contact_proof", func(t *testing.T) {
		u := f.user(t)
		session := f.signIn(t, u)
		newEmail := "changed-contact@example.com"
		f.call(t, "PUT", "/me/email", session.AccessToken, map[string]string{"email": newEmail}).want(t, http.StatusAccepted, "")
		before, err := f.auth.User(t.Context(), iam.UserByID(u.ID))
		noError(t, err)
		if before.Email == nil || *before.Email != u.Email {
			t.Fatal("unconfirmed contact replaced the current address")
		}
		proof := f.out.Last(t, iam.MessageVerification, newEmail)
		f.call(t, "POST", "/verify/confirm", session.AccessToken, map[string]string{"identifier": newEmail, "code": proof.Code}).want(t, http.StatusNoContent, "")
		u.Email = newEmail
		session = f.signIn(t, u)
		phone := "+12025550178"
		f.call(t, "PUT", "/me/phone", session.AccessToken, map[string]string{"phone_number": phone}).want(t, http.StatusAccepted, "")
		proof = f.out.Last(t, iam.MessageVerification, phone)
		f.call(t, "POST", "/verify/confirm", session.AccessToken, map[string]string{"identifier": phone, "code": proof.Code}).want(t, http.StatusNoContent, "")
		got, err := f.auth.User(t.Context(), iam.UserByID(u.ID))
		noError(t, err)
		if got.Email == nil || *got.Email != newEmail || !got.EmailVerified || got.Phone == nil || *got.Phone != phone || !got.PhoneVerified {
			t.Fatal("contact confirmation has the wrong public account state")
		}
		session = f.signIn(t, u)
		f.call(t, "DELETE", "/me/phone", session.AccessToken, nil).want(t, http.StatusNoContent, "")
		got, err = f.auth.User(t.Context(), iam.UserByID(u.ID))
		noError(t, err)
		if got.Phone != nil || got.Email == nil || *got.Email != newEmail {
			t.Fatal("phone removal damaged the remaining recovery contact")
		}
	})
	t.Run("AK-J06-C04_competing_contact_confirmations_have_one_owner", func(t *testing.T) {
		users := []authtest.User{f.user(t), f.user(t)}
		tokens := []iam.TokenSet{f.signIn(t, users[0]), f.signIn(t, users[1])}
		codes := make([]string, 2)
		const address = "contested-contact@example.com"
		for i := range users {
			f.call(t, "PUT", "/me/email", tokens[i].AccessToken, map[string]string{"email": address}).want(t, http.StatusAccepted, "")
			codes[i] = f.out.Last(t, iam.MessageVerification, address).Code
		}
		results := make([]response, 2)
		errs := make([]error, 2)
		start := make(chan struct{})
		var wg sync.WaitGroup
		for i := range users {
			wg.Add(1)
			go func() {
				defer wg.Done()
				<-start
				results[i], errs[i] = f.request(t.Context(), "POST", "/verify/confirm", tokens[i].AccessToken, map[string]string{"identifier": address, "code": codes[i]})
			}()
		}
		close(start)
		wg.Wait()
		winners := 0
		for i, r := range results {
			noError(t, errs[i])
			user, err := f.auth.User(t.Context(), iam.UserByID(users[i].ID))
			noError(t, err)
			if r.status == http.StatusNoContent {
				winners++
				if user.Email == nil || *user.Email != address {
					t.Fatal("successful contact change was not committed")
				}
			} else {
				r.want(t, http.StatusBadRequest, "email_in_use")
				if user.Email == nil || *user.Email != users[i].Email {
					t.Fatal("failed contact claim changed the losing account")
				}
			}
		}
		if winners != 1 {
			t.Fatalf("contact claim produced %d owners", winners)
		}
	})
	t.Run("AK-J06-C05_self_recovery_cannot_restore_admin_deletion", func(t *testing.T) {
		g := newFixture(t)
		noError(t, g.auth.Start(context.Background()))
		u := g.user(t)
		session := g.signIn(t, u)
		g.call(t, "DELETE", "/me", session.AccessToken, nil).want(t, http.StatusNoContent, "")
		r := g.call(t, "POST", "/password/login", "", map[string]string{"identifier": u.Email, "password": u.Password})
		r.want(t, http.StatusOK, "")
		var recovery struct {
			Status   string        `json:"status"`
			Tokens   *iam.TokenSet `json:"token_set"`
			Recovery struct {
				Token string `json:"token"`
			} `json:"recovery"`
		}
		decode(t, r.body, &recovery)
		if recovery.Status != "account_recovery_required" || recovery.Tokens != nil || recovery.Recovery.Token == "" {
			t.Fatalf("self deletion did not require recovery proof: %s", r.body)
		}
		g.call(t, "POST", "/account/recovery/confirm", "", map[string]string{"token": recovery.Recovery.Token}).want(t, http.StatusNoContent, "")
		g.signIn(t, u)
		result, err := g.auth.DeleteUsers(t.Context(), iam.SystemIdentity(), []string{u.ID})
		noError(t, err)
		if len(result) != 1 || result[0].Err != nil {
			t.Fatalf("admin deletion failed: %+v", result)
		}
		g.call(t, "POST", "/password/login", "", map[string]string{"identifier": u.Email, "password": u.Password}).want(t, http.StatusUnauthorized, "account_disabled")
		_, err = g.auth.User(t.Context(), iam.UserByID(u.ID))
		if !errors.Is(err, iam.ErrUserNotFound) {
			t.Fatal("admin-deleted account remained in active reads")
		}
		result, err = g.auth.RestoreUsers(t.Context(), iam.SystemIdentity(), []string{u.ID})
		noError(t, err)
		if len(result) != 1 || result[0].Err != nil {
			t.Fatalf("authorized restore failed: %+v", result)
		}
		g.signIn(t, u)
	})
	t.Run("AK-J06-C06_last_native_recovery_contact_cannot_be_removed", func(t *testing.T) {
		const phone = "+12025550179"
		u, err := f.auth.CreateUser(t.Context(), iam.NewUser{Phone: phone, PhoneVerified: true, Username: "phoneonlyrecovery"})
		noError(t, err)
		f.call(t, "POST", "/passwordless/start", "", map[string]string{"identifier": phone, "mode": "login"}).want(t, http.StatusAccepted, "")
		code := f.out.Last(t, iam.MessageVerification, phone).Code
		tokens := tokensFrom(t, f.call(t, "POST", "/passwordless/confirm", "", map[string]string{"identifier": phone, "code": code}), u.ID)
		f.call(t, "DELETE", "/me/phone", tokens.AccessToken, nil).want(t, http.StatusConflict, "cannot_remove_last_contact")
		user, err := f.auth.User(t.Context(), iam.UserByID(u.ID))
		noError(t, err)
		if user.Phone == nil || *user.Phone != phone || !user.PhoneVerified {
			t.Fatal("refused unlink removed the last recovery contact")
		}
	})
}
