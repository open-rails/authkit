package engine

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	jwt "github.com/golang-jwt/jwt/v5"
	"github.com/jackc/pgx/v5"
	"github.com/open-rails/authkit/internal/authflow"
	"github.com/open-rails/authkit/internal/db"
	"github.com/open-rails/authkit/internal/errmodel"
)

// Two-factor authentication: enrolment (factors + backup codes), the account
// gate, login and step-up code send/verify, challenges, and factor resolution.
// TOTP crypto and phone-2FA-setup codes live in flow_totp.go; this file is the
// account-level 2FA machine on top of the mfa_factors/mfa_settings tables.

// factorEnable is one factor insert. Phone and Email are the destination the
// setup code proved; the factor stays bound to it. ProvenSessionID names the
// session whose holder just proved possession of the new factor (#389).
type factorEnable struct {
	UserID          string
	Method          string
	Phone           *string
	Email           *string
	TOTPSecret      []byte
	LastTOTPStep    *int64
	MakeDefault     bool
	Mode            authflow.FactorEnrollmentMode
	ProvenSessionID string
}

// enable2FA returns the new plaintext backup codes (if any) and whether
// ProvenSessionID was marked 2FA-verified.
func (s *Engine) enable2FA(ctx context.Context, in factorEnable) ([]string, bool, error) {
	userID, method, phoneNumber, totpSecret, lastTOTPStep, makeDefault, mode := in.UserID, in.Method, in.Phone, in.TOTPSecret, in.LastTOTPStep, in.MakeDefault, in.Mode
	if s.pg == nil {
		return nil, false, fmt.Errorf("postgres not configured")
	}

	if mode != authflow.FirstFactorOnly && mode != authflow.AllowAdditionalFactors {
		return nil, false, fmt.Errorf("invalid factor enrollment mode")
	}
	method = strings.ToLower(strings.TrimSpace(method))
	if method != "email" && method != "sms" && method != "totp" {
		return nil, false, fmt.Errorf("invalid 2FA method: must be 'email', 'sms', or 'totp'")
	}
	if method == "sms" && (phoneNumber == nil || *phoneNumber == "") {
		return nil, false, fmt.Errorf("phone number required for SMS 2FA")
	}
	if method == "totp" && len(totpSecret) == 0 {
		return nil, false, fmt.Errorf("totp secret required for TOTP 2FA")
	}

	tx, err := s.pg.Begin(ctx)
	if err != nil {
		return nil, false, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	qtx := s.qtx(tx)
	if proof, ok := ctx.Value(loginEnrollmentKey{}).(loginProof); ok {
		if _, err := s.lockLoginAccount(ctx, qtx, userID, proof.Version); err != nil {
			return nil, false, err
		}
		if _, err := s.loadLoginProof(ctx, userID, proof.nonce); err != nil {
			return nil, false, err
		}
		if err := s.validateLoginProofSource(ctx, tx, proof); err != nil {
			return nil, false, err
		}
	} else if _, err := qtx.MFALockUser(ctx, userID); err != nil {
		return nil, false, err
	}

	var currentBackupCodes []string
	if settings, err := qtx.MFASettingsByUser(ctx, userID); err == nil && settings.Enabled {
		currentBackupCodes = settings.BackupCodes
	} else if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return nil, false, err
	}

	factors, err := qtx.MFAListFactorsByUser(ctx, userID)
	if err != nil {
		return nil, false, err
	}
	firstFactor := len(factors) == 0
	if mode == authflow.FirstFactorOnly && !firstFactor {
		return nil, false, errmodel.ErrTwoFAFactorExists
	}
	for _, factor := range factors {
		if factor.Method == method {
			return nil, false, errmodel.ErrTwoFAFactorExists
		}
	}
	makeDefault = makeDefault || firstFactor

	plaintextCodes := []string(nil)
	if len(currentBackupCodes) == 0 {
		plaintextCodes, currentBackupCodes = generateBackupCodes()
	}

	if makeDefault {
		if err := qtx.MFAClearDefaultFactors(ctx, userID); err != nil {
			return nil, false, err
		}
	}
	var email *string
	if method == "email" {
		email = in.Email
	}
	_, err = qtx.MFAInsertFactor(ctx, db.MFAInsertFactorParams{
		UserID:       userID,
		Method:       method,
		PhoneNumber:  phoneNumber,
		TotpSecret:   totpSecret,
		LastTotpStep: lastTOTPStep,
		IsDefault:    makeDefault,
		Email:        email,
	})
	if err != nil {
		return nil, false, err
	}

	// Settings holds only the account-level gate + backup codes (#125).
	if err := qtx.MFAUpsertSettings(ctx, db.MFAUpsertSettingsParams{
		UserID:      userID,
		BackupCodes: currentBackupCodes,
	}); err != nil {
		return nil, false, err
	}
	verified, err := s.markEnrollingSessionTx(ctx, qtx, userID, in.ProvenSessionID, method)
	if err != nil {
		return nil, false, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, false, err
	}
	return plaintextCodes, verified, nil
}

// markEnrollingSessionTx records the enrollment code as the session's second
// factor, exactly as POST /step-up/2fa with the new factor would. An email/SMS
// factor on the channel that was the session's first factor is not independent.
func (s *Engine) markEnrollingSessionTx(ctx context.Context, q *db.Queries, userID, sessionID, method string) (bool, error) {
	if strings.TrimSpace(sessionID) == "" {
		return false, nil
	}
	fresh, err := q.SessionFreshSinceForUpdate(ctx, db.SessionFreshSinceForUpdateParams{UserID: userID, SessionID: sessionID, Issuer: s.cfg.Token.Issuer})
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if !independentFactor(loginProof{Input: loginSessionInput{AuthMethods: fresh.AuthMethods}}, authflow.TwoFactorFactor{Method: method}) {
		return false, nil
	}
	n, err := q.SessionMarkAuthenticated(ctx, db.SessionMarkAuthenticatedParams{
		SessionID: sessionID, UserID: userID, Issuer: s.cfg.Token.Issuer,
		AuthMethods: authflow.NormalizeAuthMethods([]string{method, "otp", "mfa"}),
	})
	return n > 0, err
}

// Disable2FAWithRemovedRoles disables account MFA and removes active user role
// assignments whose catalog role requires MFA.
func (s *Engine) Disable2FAWithRemovedRoles(ctx context.Context, userID string) ([]authflow.RemovedMFARoleAssignment, error) {
	if s.pg == nil {
		return nil, fmt.Errorf("postgres not configured")
	}

	tx, err := s.beginAuthorityTransaction(ctx)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	q := tx
	if err := s.lockAuthority(ctx, q); err != nil {
		return nil, err
	}
	qtx := s.qtx(tx)
	if _, err := qtx.MFALockUser(ctx, userID); err != nil {
		return nil, err
	}
	removed, err := s.removeMFARequiredUserRoles(ctx, q, strings.TrimSpace(userID))
	if err != nil {
		return nil, err
	}
	if err := qtx.MFADeleteAllFactors(ctx, userID); err != nil {
		return nil, err
	}
	if err := qtx.MFADisable(ctx, userID); err != nil {
		return nil, err
	}
	return removed, tx.Commit(ctx)
}

func (s *Engine) Disable2FAFactorWithRemovedRoles(ctx context.Context, userID, factorID string) ([]authflow.RemovedMFARoleAssignment, error) {
	if s.pg == nil {
		return nil, fmt.Errorf("postgres not configured")
	}
	if strings.TrimSpace(factorID) == "" {
		return nil, fmt.Errorf("factor id required")
	}
	tx, err := s.beginAuthorityTransaction(ctx)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	q := tx
	if err := s.lockAuthority(ctx, q); err != nil {
		return nil, err
	}
	qtx := s.qtx(tx)
	if _, err := qtx.MFALockUser(ctx, userID); err != nil {
		return nil, err
	}
	rows, err := qtx.MFADeleteFactor(ctx, db.MFADeleteFactorParams{UserID: userID, ID: factorID})
	if err != nil {
		return nil, err
	}
	if rows == 0 {
		return nil, pgx.ErrNoRows
	}
	factors, err := qtx.MFAListFactorsByUser(ctx, userID)
	if err != nil {
		return nil, err
	}
	removed := []authflow.RemovedMFARoleAssignment(nil)
	if len(factors) == 0 {
		removed, err = s.removeMFARequiredUserRoles(ctx, q, strings.TrimSpace(userID))
		if err != nil {
			return nil, err
		}
		if err := qtx.MFADisable(ctx, userID); err != nil {
			return nil, err
		}
		return removed, tx.Commit(ctx)
	}
	// Promote a new default if the deleted factor was the default.
	hasDefault := false
	for _, f := range factors {
		if f.IsDefault {
			hasDefault = true
			break
		}
	}
	if !hasDefault {
		if _, err := qtx.MFASetDefaultFactor(ctx, db.MFASetDefaultFactorParams{UserID: userID, ID: factors[0].ID}); err != nil {
			return nil, err
		}
	}
	return removed, tx.Commit(ctx)
}

func (s *Engine) setDefault2FAFactor(ctx context.Context, userID, factorID string) error {
	if s.pg == nil {
		return fmt.Errorf("postgres not configured")
	}
	if strings.TrimSpace(factorID) == "" {
		return fmt.Errorf("factor id required")
	}
	tx, err := s.pg.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	qtx := s.qtx(tx)
	if _, err := qtx.MFALockUser(ctx, userID); err != nil {
		return err
	}
	factors, err := qtx.MFAListFactorsByUser(ctx, userID)
	if err != nil {
		return err
	}
	var selected *db.MfaFactor
	for i := range factors {
		if factors[i].ID == factorID {
			selected = &factors[i]
			break
		}
	}
	if selected == nil {
		return pgx.ErrNoRows
	}
	if err := qtx.MFAClearDefaultFactors(ctx, userID); err != nil {
		return err
	}
	if _, err := qtx.MFASetDefaultFactor(ctx, db.MFASetDefaultFactorParams{UserID: userID, ID: factorID}); err != nil {
		return err
	}
	_ = selected // existence check only; per-factor data is not mirrored to settings (#125)
	return tx.Commit(ctx)
}

// Get2FASettings retrieves a user's 2FA settings
func (s *Engine) Get2FASettings(ctx context.Context, userID string) (*authflow.TwoFactorSettings, error) {
	if s.pg == nil {
		return nil, fmt.Errorf("postgres not configured")
	}

	return s.get2FASettings(ctx, s.q, userID)
}

func (s *Engine) get2FASettings(ctx context.Context, q *db.Queries, userID string) (*authflow.TwoFactorSettings, error) {
	row, err := q.MFASettingsByUser(ctx, userID)
	if err != nil {
		return nil, err
	}
	// Settings holds only the account gate + backup codes (#125); the displayed
	// method/phone/secret are derived from the default factor below.
	settings := &authflow.TwoFactorSettings{
		UserID:      row.UserID,
		Enabled:     row.Enabled,
		BackupCodes: row.BackupCodes,
		CreatedAt:   row.CreatedAt,
		UpdatedAt:   row.UpdatedAt,
	}
	factors, err := s.list2FAFactors(ctx, q, userID)
	if err != nil {
		return nil, err
	}
	settings.Factors = factors
	for _, factor := range factors {
		if factor.IsDefault {
			settings.Method = factor.Method
			settings.PhoneNumber = factor.PhoneNumber
			settings.TOTPSecret = factor.TOTPSecret
			settings.LastTOTPStep = factor.LastTOTPStep
			break
		}
	}
	return settings, nil
}

func (s *Engine) listUser2FAFactors(ctx context.Context, userID string) ([]authflow.TwoFactorFactor, error) {
	if s.pg == nil {
		return nil, fmt.Errorf("postgres not configured")
	}
	return s.list2FAFactors(ctx, s.q, userID)
}

func (s *Engine) list2FAFactors(ctx context.Context, q *db.Queries, userID string) ([]authflow.TwoFactorFactor, error) {
	rows, err := q.MFAListFactorsByUser(ctx, userID)
	if err != nil {
		return nil, err
	}
	out := make([]authflow.TwoFactorFactor, 0, len(rows))
	for _, row := range rows {
		out = append(out, twoFactorFactorFromFields(row))
	}
	return out, nil
}

func (s *Engine) send2FACodeForFactor(ctx context.Context, userID, sessionID string, factor authflow.TwoFactorFactor) (string, error) {
	if !factor.Enabled {
		return "", fmt.Errorf("2FA not enabled")
	}
	if factor.Method == "totp" {
		return "authenticator app", nil
	}
	user, err := s.getUserByID(ctx, userID)
	if err != nil {
		return "", err
	}

	return s.send2FACodeForUser(ctx, user, sessionID, factor)
}

// send2FACodeForUser sends a code for factor to the destination pinned at its
// enrollment (never the account's current address), stored under scope: the
// login proof, step-up session or device-key ceremony it answers.
func (s *Engine) send2FACodeForUser(ctx context.Context, user *userRecord, scope string, factor authflow.TwoFactorFactor) (string, error) {
	userID := user.ID
	language := ""
	if user.PreferredLanguage != nil {
		language = *user.PreferredLanguage
	}
	if factor.Method == "totp" {
		return "authenticator app", nil
	}
	if strings.TrimSpace(scope) == "" {
		return "", fmt.Errorf("2FA code scope required")
	}
	code := randAlphanumeric(6)
	hash := sha256Hex(code)

	var destination string
	if factor.Method == "email" {
		if factor.Email == nil {
			return "", fmt.Errorf("no email address pinned to the email factor")
		}
		destination = *factor.Email
	} else { // sms
		if factor.PhoneNumber == nil {
			return "", fmt.Errorf("no phone number configured for SMS 2FA")
		}
		destination = *factor.PhoneNumber
	}

	if !s.useEphemeralStore() {
		return "", fmt.Errorf("ephemeral store not configured")
	}
	if err := s.storeMFAStepUpCode(ctx, userID, scope, hash, factor.Method, destination); err != nil {
		return "", err
	}

	username := ""
	if user.Username != nil {
		username = *user.Username
	}

	if factor.Method == "email" {
		if s.email != nil {
			sendCtx := contextWithPreferredLanguage(ctx, language)
			if err := s.withSendTimeout(sendCtx, func(sendCtx context.Context) error {
				return s.email.SendLoginCode(sendCtx, destination, username, code)
			}); err != nil {
				return "", emailDeliveryError(err)
			}
		} else {
			// In production, require email to be configured for email 2FA
			if !s.cfg.Registration.AllowMissingSenders {
				return "", fmt.Errorf("email 2FA unavailable: email sender not configured (email 2FA requires email in production)")
			}
		}
	} else { // sms
		if s.sms != nil {
			sendCtx := contextWithPreferredLanguage(ctx, language)
			if err := s.withSendTimeout(sendCtx, func(sendCtx context.Context) error { return s.sms.SendLoginCode(sendCtx, destination, code) }); err != nil {
				return "", smsDeliveryError(err)
			}
		} else {
			// In production, require SMS to be configured for SMS 2FA
			if !s.cfg.Registration.AllowMissingSenders {
				return "", fmt.Errorf("SMS 2FA unavailable: SMS sender not configured (SMS 2FA requires delivery in production)")
			}
		}
	}
	return destination, nil
}

func (s *Engine) Require2FAForStepUpMethod(ctx context.Context, userID, sessionID, method string) (destination, selectedMethod string, factor authflow.TwoFactorFactor, err error) {
	if strings.TrimSpace(sessionID) == "" {
		return "", "", authflow.TwoFactorFactor{}, jwt.ErrTokenInvalidClaims
	}
	factor, err = s.twoFactorFactorByMethod(ctx, userID, method)
	if err != nil {
		return "", "", authflow.TwoFactorFactor{}, err
	}
	destination, err = s.send2FACodeForFactor(ctx, userID, sessionID, factor)
	return destination, factor.Method, factor, err
}

func (s *Engine) Verify2FAStepUpMethodCode(ctx context.Context, userID, sessionID, method, code string) (bool, error) {
	if strings.TrimSpace(sessionID) == "" {
		return false, jwt.ErrTokenInvalidClaims
	}
	factor, err := s.twoFactorFactorByMethod(ctx, userID, method)
	if err != nil {
		return false, err
	}
	return s.verifyStepUpForFactor(ctx, userID, sessionID, code, factor)
}

// verifyStepUpForFactor is the shared step-up verify tail once the factor is
// resolved (by id or by method): TOTP verifies inline, everything else consumes
// the session-scoped code from the ephemeral store.
func (s *Engine) verifyStepUpForFactor(ctx context.Context, userID, sessionID, code string, factor authflow.TwoFactorFactor) (bool, error) {
	if factor.Method == "totp" {
		return s.verifyTOTPFactorCode(ctx, factor, code)
	}
	if !s.useEphemeralStore() {
		return false, fmt.Errorf("ephemeral store not configured")
	}
	return s.consumeMFAStepUpCode(ctx, userID, sessionID, sha256Hex(code), factor.Method)
}

func (s *Engine) verifyTOTPFactorCode(ctx context.Context, factor authflow.TwoFactorFactor, code string) (bool, error) {
	return s.verifyTOTPFactorCodeOn(ctx, s.q, factor, code)
}

func (s *Engine) verifyTOTPFactorCodeOn(ctx context.Context, q *db.Queries, factor authflow.TwoFactorFactor, code string) (bool, error) {
	secret, err := s.decryptTOTPSecret(factor.TOTPSecret)
	if err != nil {
		return false, err
	}
	step, ok, err := matchingTOTPStep(secret, code, time.Now())
	if err != nil || !ok {
		return false, err
	}
	if strings.TrimSpace(factor.ID) == "" {
		return false, fmt.Errorf("totp factor has no id")
	}
	rows, err := q.MFAConsumeFactorTOTPStep(ctx, db.MFAConsumeFactorTOTPStepParams{ID: factor.ID, UserID: factor.UserID, Step: &step})
	return rows > 0, err
}

// VerifyBackupCode verifies a 2FA backup code for account recovery.
// On success, removes the used backup code from the user's backup codes.
func (s *Engine) VerifyBackupCode(ctx context.Context, userID, backupCode string) (bool, error) {
	return s.verifyBackupCode(ctx, s.q, userID, backupCode)
}

func (s *Engine) verifyBackupCode(ctx context.Context, q *db.Queries, userID, backupCode string) (bool, error) {
	if s.pg == nil {
		return false, fmt.Errorf("postgres not configured")
	}

	// Atomic single-use consume in one statement: the DB removes the hashed code
	// and reports whether THIS call was the one that removed it. This replaces the
	// former read-filter-rewrite, which let two concurrent submissions of the same
	// code both succeed. The query's `enabled = true` predicate also subsumes the
	// old "2FA not enabled" check (callers treat (false, nil) and that error
	// identically — both reject the code).
	hash := sha256Hex(backupCode)
	rows, err := q.MFAConsumeBackupCode(ctx, db.MFAConsumeBackupCodeParams{CodeHash: hash, UserID: userID})
	if err != nil {
		return false, err
	}
	return rows == 1, nil
}

// RegenerateBackupCodes generates new backup codes for a user (invalidating old ones).
// Returns the plaintext codes (caller must show these to user ONCE).
func (s *Engine) RegenerateBackupCodes(ctx context.Context, userID string) ([]string, error) {
	if s.pg == nil {
		return nil, fmt.Errorf("postgres not configured")
	}

	// Verify 2FA is enabled
	settings, err := s.Get2FASettings(ctx, userID)
	if err != nil || !settings.Enabled {
		return nil, fmt.Errorf("2FA not enabled")
	}

	plaintextCodes, hashedCodes := generateBackupCodes()
	if err := s.q.MFASetBackupCodes(ctx, db.MFASetBackupCodesParams{BackupCodes: hashedCodes, UserID: userID}); err != nil {
		return nil, err
	}

	return plaintextCodes, nil
}

func (s *Engine) twoFactorFactor(ctx context.Context, userID, factorID string) (authflow.TwoFactorFactor, error) {
	if s.pg == nil {
		return authflow.TwoFactorFactor{}, fmt.Errorf("postgres not configured")
	}
	factors, err := s.listUser2FAFactors(ctx, userID)
	if err != nil {
		return authflow.TwoFactorFactor{}, err
	}
	if len(factors) == 0 {
		settings, err := s.Get2FASettings(ctx, userID)
		if err != nil || !settings.Enabled || len(settings.Factors) == 0 {
			return authflow.TwoFactorFactor{}, fmt.Errorf("2FA not enabled")
		}
		factors = settings.Factors
	}
	if strings.TrimSpace(factorID) != "" {
		for _, factor := range factors {
			if factor.ID == factorID {
				return factor, nil
			}
		}
		return authflow.TwoFactorFactor{}, pgx.ErrNoRows
	}
	for _, factor := range factors {
		if factor.IsDefault {
			return factor, nil
		}
	}
	return factors[0], nil
}

func (s *Engine) twoFactorFactorByMethod(ctx context.Context, userID, method string) (authflow.TwoFactorFactor, error) {
	method = strings.ToLower(strings.TrimSpace(method))
	if method == "" {
		return s.twoFactorFactor(ctx, userID, "")
	}
	if method != "email" && method != "sms" && method != "totp" {
		return authflow.TwoFactorFactor{}, fmt.Errorf("invalid 2FA method: must be 'email', 'sms', or 'totp'")
	}
	factors, err := s.listUser2FAFactors(ctx, userID)
	if err != nil {
		return authflow.TwoFactorFactor{}, err
	}
	if len(factors) == 0 {
		settings, err := s.Get2FASettings(ctx, userID)
		if err != nil || !settings.Enabled || len(settings.Factors) == 0 {
			return authflow.TwoFactorFactor{}, fmt.Errorf("2FA not enabled")
		}
		factors = settings.Factors
	}
	for _, factor := range factors {
		if factor.Enabled && strings.EqualFold(factor.Method, method) {
			return factor, nil
		}
	}
	return authflow.TwoFactorFactor{}, pgx.ErrNoRows
}

func twoFactorFactorFromFields(row db.MfaFactor) authflow.TwoFactorFactor {
	return authflow.TwoFactorFactor{
		ID:           row.ID,
		UserID:       row.UserID,
		Method:       row.Method,
		PhoneNumber:  row.PhoneNumber,
		Email:        row.Email,
		TOTPSecret:   row.TotpSecret,
		LastTOTPStep: row.LastTotpStep,
		IsDefault:    row.IsDefault,
		Enabled:      true, // #125: a factor row existing IS the enabled state
		CreatedAt:    row.CreatedAt,
		UpdatedAt:    row.UpdatedAt,
	}
}

func generateBackupCodes() (plaintextCodes, hashedCodes []string) {
	plaintextCodes = make([]string, 10)
	hashedCodes = make([]string, 10)
	for i := 0; i < 10; i++ {
		code := randAlphanumericUppercase(8)
		plaintextCodes[i] = code
		hashedCodes[i] = sha256Hex(code)
	}
	return plaintextCodes, hashedCodes
}
