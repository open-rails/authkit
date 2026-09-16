package embedded

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/open-rails/authkit/internal/db"
	"github.com/open-rails/authkit/internal/testdb"
	"github.com/stretchr/testify/require"
)

func TestResetGrantRejectsLegacyAndChangedRecoveryChannels(t *testing.T) {
	svc, _ := newHardeningService(t)
	ctx := context.Background()
	u, email := newHardeningUser(t, ctx, svc, "grants")
	require.NoError(t, svc.ephemSetJSON(ctx, keyPasswordReset+sha256Hex("legacy"), map[string]any{"user_id": u.ID}, time.Minute))
	_, err := svc.ConfirmPasswordReset(ctx, "legacy", "Replacement-password-12345")
	require.Error(t, err)

	phone := "+12025550111"
	require.NoError(t, svc.q.UserSetPhoneAndVerified(ctx, db.UserSetPhoneAndVerifiedParams{ID: u.ID, PhoneNumber: &phone, PhoneVerified: true}))
	require.NoError(t, svc.storePasswordReset(ctx, sha256Hex("phone"), u.ID, "sms", phone, time.Minute))
	// A writer outside the request finalizer still invalidates the old grant.
	replacement := "+12025550112"
	require.NoError(t, svc.q.UserSetPhoneAndVerified(ctx, db.UserSetPhoneAndVerifiedParams{ID: u.ID, PhoneNumber: &replacement, PhoneVerified: true}))
	_, err = svc.ConfirmPasswordReset(ctx, "phone", "Replacement-password-12345")
	require.Error(t, err)
	require.Error(t, svc.storePasswordReset(ctx, sha256Hex("old-contact"), u.ID, "sms", phone, time.Minute))

	require.NoError(t, svc.storePasswordReset(ctx, sha256Hex("ban"), u.ID, "email", email, time.Minute))
	_, err = svc.pg.Exec(ctx, `UPDATE profiles.users SET banned_at=now() WHERE id=$1`, u.ID)
	require.NoError(t, err)
	require.NoError(t, svc.q.UserClearBan(ctx, u.ID))
	_, err = svc.ConfirmPasswordReset(ctx, "ban", "Replacement-password-12345")
	require.Error(t, err, "unbanning must not revive an old grant")

	require.NoError(t, svc.storePasswordReset(ctx, sha256Hex("current"), u.ID, "email", email, time.Minute))
	_, err = svc.ConfirmPasswordReset(ctx, "current", "Replacement-password-12345")
	require.NoError(t, err)
	_, err = svc.ConfirmPasswordReset(ctx, "current", "Another-password-12345")
	require.Error(t, err)
}

func TestCredentialChangesHaveOneConcurrentWinner(t *testing.T) {
	for _, kind := range []string{"reset", "current_password"} {
		t.Run(kind, func(t *testing.T) {
			svc, _ := newHardeningService(t)
			ctx := context.Background()
			u, email := newHardeningUser(t, ctx, svc, "parallel")
			require.NoError(t, svc.AdminSetPassword(ctx, u.ID, "Original-password-12345"))
			for _, token := range []string{"reset-a", "reset-b"} {
				require.NoError(t, svc.storePasswordReset(ctx, sha256Hex(token), u.ID, "email", email, time.Minute))
			}
			lock, err := svc.pg.Begin(ctx)
			require.NoError(t, err)
			defer lock.Rollback(ctx)
			_, err = svc.qtx(lock).UserCredentialVersionForUpdate(ctx, u.ID)
			require.NoError(t, err)
			// The fixture lock, blocker and two workers occupy four connections.
			// Observe through a separate pool so CI's four-connection pool cannot
			// starve the query that proves both workers reached the database lock.
			observer := testdb.UnlockedPool(t)
			result := make(chan error, 2)
			for i := range 2 {
				go func() {
					newPassword := fmt.Sprintf("Replacement-password-%d", i)
					if kind == "reset" {
						_, err := svc.ConfirmPasswordReset(ctx, []string{"reset-a", "reset-b"}[i], newPassword)
						result <- err
					} else {
						result <- svc.ChangePassword(ctx, u.ID, "Original-password-12345", newPassword, nil)
					}
				}()
			}
			require.Eventually(t, func() bool {
				var n int
				err := observer.QueryRow(ctx, `SELECT count(*) FROM pg_stat_activity WHERE datname=current_database() AND wait_event_type='Lock' AND query LIKE '%UserCredentialVersionForUpdate%'`).Scan(&n)
				return err == nil && n == 2
			}, 10*time.Second, 10*time.Millisecond)
			require.NoError(t, lock.Commit(ctx))
			successes := 0
			for range 2 {
				if <-result == nil {
					successes++
				}
			}
			require.Equal(t, 1, successes)
		})
	}
}

func TestProviderLinkSerializesWithRevocation(t *testing.T) {
	svc, _ := newHardeningService(t)
	ctx := context.Background()
	u, _ := newHardeningUser(t, ctx, svc, "linkrace")
	sid, _, _, err := svc.IssueRefreshSession(ctx, u.ID, "link", nil)
	require.NoError(t, err)
	fresh, err := svc.SessionFreshness(ctx, u.ID, sid, time.Now())
	require.NoError(t, err)
	link := &ExternalLinkAuthorization{UserID: u.ID, SessionID: sid, AuthenticatedAt: fresh.LastAuthenticatedAt}
	in := ExternalLoginInput{Link: link, Identity: ExternalIdentity{Provider: "test", Issuer: "https://link.test", Subject: "subject"}}
	revocation, err := svc.pg.Begin(ctx)
	require.NoError(t, err)
	defer revocation.Rollback(ctx)
	_, err = svc.qtx(revocation).SessionsRevokeAll(ctx, db.SessionsRevokeAllParams{UserID: u.ID, Issuers: []string{svc.cfg.Token.Issuer}})
	require.NoError(t, err)
	done := make(chan error, 1)
	go func() { _, err := svc.CompleteExternalLogin(ctx, in); done <- err }()
	require.Eventually(t, func() bool {
		var n int
		err := svc.pg.QueryRow(ctx, `SELECT count(*) FROM pg_stat_activity WHERE datname=current_database() AND wait_event_type='Lock' AND query LIKE '%SessionFreshSinceForUpdate%'`).Scan(&n)
		return err == nil && n == 1
	}, 5*time.Second, 10*time.Millisecond)
	require.NoError(t, revocation.Commit(ctx))
	require.Error(t, <-done)
	_, _, err = svc.GetProviderLinkByIssuer(ctx, in.Identity.Issuer, in.Identity.Subject)
	require.Error(t, err)
	sessions, err := svc.ListUserSessions(ctx, u.ID)
	require.NoError(t, err)
	require.Empty(t, sessions)

	// Reverse order is a valid completed link followed by revocation. Linking
	// retains the original session and never creates another refresh family.
	sid, _, _, err = svc.IssueRefreshSession(ctx, u.ID, "link", nil)
	require.NoError(t, err)
	fresh, err = svc.SessionFreshness(ctx, u.ID, sid, time.Now())
	require.NoError(t, err)
	link.SessionID, link.AuthenticatedAt = sid, fresh.LastAuthenticatedAt
	out, err := svc.CompleteExternalLogin(ctx, in)
	require.NoError(t, err)
	require.Equal(t, LoginProviderLinked, out.Kind)
	require.Nil(t, out.Session)
	sessions, err = svc.ListUserSessions(ctx, u.ID)
	require.NoError(t, err)
	require.Len(t, sessions, 1)
	require.Equal(t, sid, sessions[0].ID)
	require.NoError(t, svc.RevokeIssuerSessions(ctx, u.ID, nil))
	sessions, err = svc.ListUserSessions(ctx, u.ID)
	require.NoError(t, err)
	require.Empty(t, sessions)
}

func TestCredentialCancellationRollsBack(t *testing.T) {
	svc, _ := newHardeningService(t)
	ctx := context.Background()
	u, _ := newHardeningUser(t, ctx, svc, "cancel")
	require.NoError(t, svc.AdminSetPassword(ctx, u.ID, "Original-password-12345"))
	sid, _, _, err := svc.IssueRefreshSession(ctx, u.ID, "cancel", nil)
	require.NoError(t, err)
	before, err := svc.q.UserCredentialVersion(ctx, u.ID)
	require.NoError(t, err)
	lock, err := svc.pg.Begin(ctx)
	require.NoError(t, err)
	defer lock.Rollback(ctx)
	_, err = svc.qtx(lock).UserCredentialVersionForUpdate(ctx, u.ID)
	require.NoError(t, err)
	changeCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- svc.AdminSetPassword(changeCtx, u.ID, "Replacement-password-12345") }()
	require.Eventually(t, func() bool {
		var n int
		err := svc.pg.QueryRow(ctx, `SELECT count(*) FROM pg_stat_activity WHERE datname=current_database() AND wait_event_type='Lock' AND query LIKE '%UserCredentialVersionForUpdate%'`).Scan(&n)
		return err == nil && n == 1
	}, 5*time.Second, 10*time.Millisecond)
	cancel()
	require.Error(t, <-done)
	require.NoError(t, lock.Commit(ctx))
	after, err := svc.q.UserCredentialVersion(ctx, u.ID)
	require.NoError(t, err)
	require.Equal(t, before.CredentialVersion, after.CredentialVersion)
	require.NoError(t, svc.CheckUserPassword(ctx, u.ID, "Original-password-12345"))
	sessions, err := svc.ListUserSessions(ctx, u.ID)
	require.NoError(t, err)
	require.Len(t, sessions, 1)
	require.Equal(t, sid, sessions[0].ID)
}
