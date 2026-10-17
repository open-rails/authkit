package engine

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/authflow"
	"github.com/open-rails/authkit/internal/db"
	"github.com/open-rails/authkit/internal/errmodel"
	"github.com/open-rails/authkit/internal/secret"
)

// Recovery codes belong to the account, not to a particular OTP factor or RP.
// Every caller holds the account lock, shared with factor/key mutations.
func (s *Engine) recoveryEnrollment(ctx context.Context, q *db.Queries, userID string) (bool, error) {
	codes, err := q.MFAUsable(ctx, userID)
	if err != nil || codes {
		return codes, err
	}
	return q.PasskeyExistsByUser(ctx, userID)
}

func (s *Engine) pruneRecoveryCodes(ctx context.Context, q *db.Queries, userID string) error {
	held, err := s.recoveryEnrollment(ctx, q, userID)
	if err != nil || held {
		return err
	}
	return q.MFASettingsDelete(ctx, userID)
}

// A later first key cannot revive an orphaned recovery set left by an older
// writer. An existing OTP factor or another RP's key retains its current set.
func (s *Engine) preparePasskeyRecovery(ctx context.Context, q *db.Queries, userID string) error {
	return s.pruneRecoveryCodes(ctx, q, userID)
}

// The HTTP path requires a live, recent strong proof while holding the same
// lock as code replacement. Trusted host callers use RegenerateBackupCodes.
func (s *Engine) RegenerateBackupCodesForSession(ctx context.Context, userID, sessionID string) ([]string, error) {
	if strings.TrimSpace(sessionID) == "" {
		return nil, errmodel.E(errmodel.CodeUnauthenticated)
	}
	return s.regenerateRecoveryCodes(ctx, userID, sessionID)
}

func (s *Engine) regenerateRecoveryCodes(ctx context.Context, userID, sessionID string) ([]string, error) {
	if s.pg == nil {
		return nil, fmt.Errorf("postgres not configured")
	}
	tx, err := s.pg.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)
	q := s.qtx(tx)
	if _, err := q.MFALockUser(ctx, userID); err != nil {
		return nil, err
	}
	held, err := s.recoveryEnrollment(ctx, q, userID)
	if err != nil {
		return nil, err
	}
	if !held {
		return nil, errmodel.ErrInvalidTwoFAMethod
	}
	if sessionID != "" {
		fresh, err := q.SessionFreshSinceForUpdate(ctx, db.SessionFreshSinceForUpdateParams{UserID: userID, SessionID: sessionID, Issuer: s.cfg.Token.Issuer})
		if err != nil {
			return nil, err
		}
		factors, err := q.MFAListFactorsByUser(ctx, userID)
		if err != nil {
			return nil, err
		}
		required, err := s.userRequiresMFA(ctx, tx, userID)
		if err != nil {
			return nil, err
		}
		recent := fresh.MfaAuthenticatedAt != nil && !fresh.MfaAuthenticatedAt.After(time.Now()) && time.Since(*fresh.MfaAuthenticatedAt) < authflow.SensitiveActionFreshAuthWindow
		strong := policyMFAProof(fresh.AuthMethods)
		if !recent || (required || len(factors) == 0) && !strong {
			return nil, s.recoveryStepUpRequired(ctx, q, userID, factors, required)
		}
	}
	plaintext, hashes := generateBackupCodes()
	if err := q.MFAUpsertSettings(ctx, db.MFAUpsertSettingsParams{UserID: userID, BackupCodes: hashes}); err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return plaintext, nil
}

// Recovery state can exist without an OTP factor. Missing state is harmless;
// an actual store failure must not become permission to enroll a replacement.
func recoveryCodesAvailable(settings *authflow.TwoFactorSettings, err error) (bool, error) {
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return settings != nil && len(settings.BackupCodes) > 0, nil
}

// CompleteTwoFactorStepUp proves the current factor under the account lock.
// A recovery code and the session freshness it authorizes commit together;
// a policy promotion cannot race an emailed proof into strong MFA freshness.
func (s *Engine) CompleteTwoFactorStepUp(ctx context.Context, userID, sessionID, factorID, code string, backup bool) error {
	if err := s.requirePG(); err != nil {
		return err
	}
	// Delivery-code attempt counters intentionally commit outside the account
	// transaction. Charge/consume before taking its connection, then recheck
	// the exact factor and policy under the account lock before any freshness
	// mutation. This also works with a one-connection pool.
	var delivered authflow.MFAFactor
	if !backup {
		selected, err := s.stepUpFactor(ctx, userID, factorID)
		if err != nil {
			return err
		}
		if !s.twoFactorMethodConfigured(iam.TwoFactorMethod(selected.Method)) {
			return errmodel.ErrInvalidTwoFAMethod
		}
		if selected.Method != "totp" {
			valid, err := s.consumeMFAStepUpCode(ctx, userID, sessionID, secret.Hash(code), selected.Method)
			if err != nil {
				return err
			}
			if !valid {
				return errmodel.ErrInvalidCode
			}
			delivered = selected
		}
	}
	tx, err := s.pg.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	q := s.qtx(tx)
	if _, err = q.MFALockUser(ctx, userID); err != nil {
		return err
	}
	if _, err = q.SessionFreshSinceForUpdate(ctx, db.SessionFreshSinceForUpdateParams{UserID: userID, SessionID: sessionID, Issuer: s.cfg.Token.Issuer}); err != nil {
		return err
	}
	settings, err := s.get2FASettings(ctx, q, userID)
	if errors.Is(err, pgx.ErrNoRows) {
		return errmodel.ErrInvalidTwoFAMethod
	}
	if err != nil {
		return err
	}
	required, err := s.userRequiresMFA(ctx, tx, userID)
	if err != nil {
		return err
	}
	method := "backup_code"
	valid := false
	if backup {
		held, err := s.recoveryEnrollment(ctx, q, userID)
		if err != nil {
			return err
		}
		if !held {
			return errmodel.ErrInvalidCode
		}
		valid, err = s.verifyBackupCode(ctx, q, userID, strings.TrimSpace(code))
		if err != nil {
			return err
		}
	} else {
		factors := settings.Factors
		var selected *authflow.MFAFactor
		for i := range factors {
			f := &factors[i]
			if required && !strongFactorMethod(f.Method) || !s.twoFactorMethodConfigured(iam.TwoFactorMethod(f.Method)) {
				continue
			}
			if factorID != "" && f.ID == factorID || factorID == "" && (selected == nil || f.IsDefault) {
				selected = f
			}
		}
		if selected == nil {
			return errmodel.ErrInvalidCode
		}
		method = selected.Method
		if method == "totp" {
			valid, err = s.verifyTOTPFactorCodeOn(ctx, q, *selected, code)
		} else {
			valid = delivered.ID == selected.ID && delivered.Method == method
		}
		if err != nil {
			return err
		}
	}
	if !valid {
		return errmodel.ErrInvalidCode
	}
	methods := []string{method, "otp", "mfa"}
	status, statusErr := s.mfaStatusWith(settings, nil)
	if statusErr != nil {
		return statusErr
	}
	if err := s.requireSessionMFAStateOn(ctx, tx, userID, methods, status, nil); err != nil {
		return err
	}
	n, err := q.SessionMarkAuthenticated(ctx, db.SessionMarkAuthenticatedParams{UserID: userID, SessionID: sessionID, Issuer: s.cfg.Token.Issuer, AuthMethods: methods})
	if err != nil {
		return err
	}
	if n == 0 {
		return errmodel.E(errmodel.CodeInvalidToken)
	}
	return tx.Commit(ctx)
}

// Build this error from the transaction's reads: consulting the pool again
// while holding the only connection would deadlock a minimal deployment.
func (s *Engine) recoveryStepUpRequired(ctx context.Context, q *db.Queries, userID string, factors []db.MfaFactor, required bool) error {
	wire := []authflow.TwoFactorFactor{}
	for _, factor := range factors {
		if !required || strongFactorMethod(factor.Method) {
			wire = append(wire, authflow.WireFactor(twoFactorFactorFromFields(factor)))
		}
	}
	methods := []string{}
	if len(wire) > 0 {
		methods = append(methods, "2fa")
	}
	if s.PasskeysEnabled() {
		held, err := q.PasskeyExistsForRP(ctx, db.PasskeyExistsForRPParams{UserID: userID, Rpid: s.cfg.Passkeys.RPID})
		if err != nil {
			return err
		}
		if held {
			methods = append(methods, "passkey")
		}
	}
	return errmodel.E(errmodel.CodeStepUpRequired, errmodel.WithDetails(authflow.StepUpRequired{StepUpMethods: methods, MaxAgeSeconds: int64(authflow.SensitiveActionFreshAuthWindow.Seconds()), Factors: wire}))
}
