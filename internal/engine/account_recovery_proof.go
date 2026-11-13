package engine

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	jwt "github.com/golang-jwt/jwt/v5"
	"github.com/jackc/pgx/v5"
	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/authflow"
	"github.com/open-rails/authkit/internal/db"
	"github.com/open-rails/authkit/internal/errmodel"
	"github.com/open-rails/authkit/internal/secret"
)

// accountRecoveryProof holds a finished first factor, and any second, until
// the person chooses. It is no session: only ConfirmAccountRecovery reads it.
type accountRecoveryProof struct {
	Login     loginProof `json:"login"`
	Issuer    string     `json:"issuer"`
	ExpiresAt time.Time  `json:"expires_at"`
}

func (s *Engine) ensureLoginProofAccess(ctx context.Context, user *db.User) error {
	if user == nil {
		return jwt.ErrTokenUnverifiable
	}
	copy := *user
	copy.DeletedAt = nil
	return s.ensureUserAccess(ctx, &copy)
}

// Called with the account row locked; a normal in-flight proof cannot cross a
// credential-version change or switch to a later deletion cycle.
func (s *Engine) bindRecoveryGeneration(ctx context.Context, tx pgx.Tx, user *db.User, proof *loginProof) error {
	if user.DeletedAt == nil {
		if proof.DeletionID != "" {
			return jwt.ErrTokenUnverifiable
		}
		return nil
	}
	deletion, err := s.qtx(tx).AccountDeletionRecoverable(ctx, db.AccountDeletionRecoverableParams{UserID: user.ID, DeletedAt: *user.DeletedAt})
	if errors.Is(err, pgx.ErrNoRows) {
		s.sweepDeletionsNow(ctx)
		return errmodel.E(errmodel.CodeAccountRecoveryExpired)
	}
	if err != nil {
		return err
	}
	// Only a self-deletion is undone by signing in; an account staff or the
	// system deleted comes back only through RestoreUsers (N5).
	if !selfDeleted(deletion) {
		return errmodel.E(errmodel.CodeAccountDisabled)
	}
	if proof.DeletionID != "" && proof.DeletionID != deletion.ID {
		return jwt.ErrTokenUnverifiable
	}
	proof.DeletionID = deletion.ID
	return nil
}

// sweepDeletionsNow queues this issuer's batch now, for a deletion past its
// date that its batch has not purged yet (one failing, or a fleet that was
// down). Its own transaction: the caller's rolls back, and the batch needs
// its account lock.
func (s *Engine) sweepDeletionsNow(ctx context.Context) {
	err := pgx.BeginFunc(ctx, s.pg, func(tx pgx.Tx) error {
		return s.scheduleAccountCleanupTx(ctx, tx, []string{s.cfg.Token.Issuer}, time.Now())
	})
	if err != nil {
		slog.WarnContext(ctx, "authkit: account batch not queued now; it runs at its own time", "error", err)
	}
}

func (s *Engine) finishRecoveryProof(ctx context.Context, tx pgx.Tx, proof loginProof) (authflow.LoginOutcome, error) {
	window, err := s.qtx(tx).AccountDeletionPurgeWindow(ctx, db.AccountDeletionPurgeWindowParams{ID: proof.DeletionID, UserID: proof.Input.UserID})
	if err != nil {
		return authflow.LoginOutcome{}, err
	}
	now, purgeAt := window.Now, window.PurgeAt
	expires := now.Add(10 * time.Minute)
	if purgeAt.Before(expires) {
		expires = purgeAt
	}
	token := secret.Token(32)
	record := accountRecoveryProof{Login: proof, Issuer: s.cfg.Token.Issuer, ExpiresAt: expires}
	if err := s.ephemSetJSON(ctx, "account-recovery:"+secret.Hash(token), record, expires.Sub(now)); err != nil {
		return authflow.LoginOutcome{}, err
	}
	if err := s.rememberProofRoute(ctx, "account-recovery", secret.Hash(token), expires.Sub(now)); err != nil {
		return authflow.LoginOutcome{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return authflow.LoginOutcome{}, err
	}
	tenant, _ := s.tenantID(ctx)
	return authflow.LoginOutcome{TenantID: tenant, Kind: authflow.LoginRecoveryRequired, UserID: proof.Input.UserID, ReturnTo: proof.ReturnTo, Recovery: &authflow.AccountRecoveryConfirmation{Token: token, ExpiresAt: expires, PurgeAt: purgeAt}}, nil
}

// ConfirmAccountRecovery restores the account, then continues the sign-in the
// proof holds, which passes the sign-in limits a recovery skipped. The restore
// commits first: a sign-in that then fails leaves the account back, and the
// person signs in as usual.
func (s *Engine) ConfirmAccountRecovery(ctx context.Context, token string) (authflow.LoginOutcome, error) {
	if len(token) < 32 || len(token) > 256 || strings.TrimSpace(token) != token {
		return authflow.LoginOutcome{}, jwt.ErrTokenUnverifiable
	}
	var routeErr error
	ctx, routeErr = s.proofContext(ctx, "account-recovery", secret.Hash(token))
	if routeErr != nil {
		return authflow.LoginOutcome{}, routeErr
	}
	key := "account-recovery:" + secret.Hash(token)
	var record accountRecoveryProof
	raw, ok, err := s.ephemReadJSON(ctx, key, &record)
	if err != nil {
		return authflow.LoginOutcome{}, err
	}
	proof := record.Login
	if !ok || record.Issuer != s.cfg.Token.Issuer || proof.DeletionID == "" || proof.Input.UserID == "" || proof.Version <= 0 {
		return authflow.LoginOutcome{}, jwt.ErrTokenUnverifiable
	}
	tx, err := s.pg.Begin(ctx)
	if err != nil {
		return authflow.LoginOutcome{}, err
	}
	defer tx.Rollback(ctx)
	q := s.qtx(tx)
	user, err := s.lockAuthenticationAccount(ctx, q, proof.Input.UserID, proof.Version, true)
	if err != nil {
		return authflow.LoginOutcome{}, err
	}
	if user.DeletedAt == nil {
		return authflow.LoginOutcome{}, jwt.ErrTokenUnverifiable
	}
	settings, settingsErr := s.get2FASettings(ctx, q, user.ID)
	status, err := s.mfaStatusWith(settings, settingsErr)
	if err != nil {
		return authflow.LoginOutcome{}, err
	}
	if err := s.requireSessionMFAStateOn(ctx, tx, user.ID, proof.Input.AuthMethods, status, nil); err != nil {
		return authflow.LoginOutcome{}, err
	}
	now, err := q.StatementTimestamp(ctx)
	if err != nil {
		return authflow.LoginOutcome{}, err
	}
	if !now.Before(record.ExpiresAt) {
		return authflow.LoginOutcome{}, jwt.ErrTokenUnverifiable
	}
	if err := s.claimProof(ctx, key, raw); err != nil {
		return authflow.LoginOutcome{}, err
	}
	if err := s.restoreAccountDeletionOn(ctx, tx, iam.UserIdentity(user.ID), user.ID, proof.DeletionID); err != nil {
		return authflow.LoginOutcome{}, err
	}
	// The restore moved the credential version, as the deletion did.
	current, err := q.UserCredentialVersion(ctx, user.ID)
	if err != nil {
		return authflow.LoginOutcome{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return authflow.LoginOutcome{}, err
	}
	restored := authflow.LoginOutcome{Kind: authflow.LoginRestored, UserID: user.ID}
	if proof.DeviceKey {
		return restored, nil
	}
	proof.DeletionID, proof.Version = "", current.CredentialVersion
	out, err := s.finishFirstFactor(ctx, proof)
	if err != nil {
		slog.WarnContext(ctx, "authkit: restored account's sign-in did not finish", "user_id", user.ID, "error", err)
		return restored, nil
	}
	return out, nil
}

// restoreGate parks a password sign-in to a self-deleted account at a code to
// its contact, so a password alone never reaches the restore step. The code's
// confirmation does, as a code sign-in would. Anything else about the deletion
// is finishFirstFactor's to answer.
func (s *Engine) restoreGate(ctx context.Context, in authflow.PasswordLoginInput, u *db.User) (authflow.LoginOutcome, bool, error) {
	if u.DeletedAt == nil {
		return authflow.LoginOutcome{}, false, nil
	}
	deletion, err := s.q.AccountDeletionRecoverable(ctx, db.AccountDeletionRecoverableParams{UserID: u.ID, DeletedAt: *u.DeletedAt})
	if errors.Is(err, pgx.ErrNoRows) {
		return authflow.LoginOutcome{}, false, nil
	}
	if err != nil {
		return authflow.LoginOutcome{}, true, err
	}
	if !selfDeleted(deletion) {
		return authflow.LoginOutcome{}, false, nil
	}
	s.loginFailed(ctx, in, u.ID, "account_deleted")
	if u.Email != nil && s.EmailAvailable() {
		if err := s.sendEmailVerificationCode(ctx, u, defaultEmailVerificationTTL); err != nil {
			return authflow.LoginOutcome{}, true, stageErr("send_email_verification", fmt.Errorf("%w: %w", errmodel.ErrEmailVerificationSendFailed, err))
		}
		return s.verificationRequired(ctx, u.ID, *u.Email, "email", defaultEmailVerificationTTL)
	}
	if u.PhoneNumber != nil && s.SMSAvailable() {
		if err := s.sendPhoneVerificationToUser(ctx, *u.PhoneNumber, u.ID, 0); err != nil {
			return authflow.LoginOutcome{}, true, stageErr("send_phone_verification", fmt.Errorf("%w: %w", errmodel.ErrPhoneVerificationSendFailed, err))
		}
		return s.verificationRequired(ctx, u.ID, *u.PhoneNumber, "phone", defaultPhoneVerificationTTL)
	}
	return authflow.LoginOutcome{}, true, errmodel.ErrVerificationUnavailable
}

// deviceKeyRecovery stops a device-key enrollment on a deleted account at the
// same proof a sign-in reaches, with no key enrolled and the ceremony live.
func (s *Engine) deviceKeyRecovery(ctx context.Context, user *db.User, methods []string) error {
	version, err := s.q.UserCredentialVersion(ctx, user.ID)
	if err != nil {
		return err
	}
	tx, err := s.pg.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	account, err := s.lockAuthenticationAccount(ctx, s.qtx(tx), user.ID, version.CredentialVersion, true)
	if err != nil {
		return err
	}
	proof := loginProof{Version: version.CredentialVersion, AuthenticatedAt: time.Now().UTC(), DeviceKey: true,
		Input: loginSessionInput{UserID: user.ID, AuthMethods: methods, Event: "device_key_enrollment"}}
	if err := s.bindRecoveryGeneration(ctx, tx, account, &proof); err != nil {
		return err
	}
	out, err := s.finishRecoveryProof(ctx, tx, proof)
	if err != nil {
		return err
	}
	return &authflow.DeviceKeyRecoveryRequired{Confirmation: *out.Recovery}
}
