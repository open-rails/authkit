package authcore

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	jwt "github.com/golang-jwt/jwt/v5"
	"github.com/jackc/pgx/v5"
	authkit "github.com/open-rails/authkit"
	"github.com/open-rails/authkit/internal/db"
)

// Two-factor authentication: enrolment (factors + backup codes), the account
// gate, login and step-up code send/verify, challenges, and factor resolution.
// TOTP crypto and phone-2FA-setup codes live in totp.go; this file is the
// account-level 2FA machine on top of the mfa_factors/mfa_settings tables.

type TwoFactorSettings struct {
	UserID       string
	Enabled      bool
	Method       string // "email", "sms", or "totp"
	PhoneNumber  *string
	TOTPSecret   []byte
	LastTOTPStep *int64
	BackupCodes  []string // Hashed backup codes
	Factors      []TwoFactorFactor
	CreatedAt    time.Time
	UpdatedAt    time.Time
}

type TwoFactorFactor struct {
	ID           string
	UserID       string
	Method       string
	PhoneNumber  *string
	TOTPSecret   []byte
	LastTOTPStep *int64
	IsDefault    bool
	Enabled      bool
	CreatedAt    time.Time
	UpdatedAt    time.Time
}

// FactorEnrollmentMode distinguishes restricted enrollment grants from authenticated factor management.
type FactorEnrollmentMode string

const (
	// FirstFactorOnly permits a restricted grant to enroll only when no factor exists.
	FirstFactorOnly FactorEnrollmentMode = "first_factor_only"
	// AllowAdditionalFactors permits fresh authenticated users to add a new method.
	AllowAdditionalFactors FactorEnrollmentMode = "allow_additional_factors"
)

// Enable2FA enables two-factor authentication for a user and generates backup codes.
// Returns the plaintext backup codes (caller must show these to user ONCE).
func (s *Service) Enable2FA(ctx context.Context, userID, method string, phoneNumber *string, mode FactorEnrollmentMode) ([]string, error) {
	return s.enable2FA(ctx, userID, method, phoneNumber, nil, nil, false, mode)
}

func (s *Service) Enable2FADefault(ctx context.Context, userID, method string, phoneNumber *string, mode FactorEnrollmentMode) ([]string, error) {
	return s.enable2FA(ctx, userID, method, phoneNumber, nil, nil, true, mode)
}

func (s *Service) enable2FA(ctx context.Context, userID, method string, phoneNumber *string, totpSecret []byte, lastTOTPStep *int64, makeDefault bool, mode FactorEnrollmentMode) ([]string, error) {
	if s.pg == nil {
		return nil, fmt.Errorf("postgres not configured")
	}

	if mode != FirstFactorOnly && mode != AllowAdditionalFactors {
		return nil, fmt.Errorf("invalid factor enrollment mode")
	}
	method = strings.ToLower(strings.TrimSpace(method))
	if method != "email" && method != "sms" && method != "totp" {
		return nil, fmt.Errorf("invalid 2FA method: must be 'email', 'sms', or 'totp'")
	}
	if method == "sms" && (phoneNumber == nil || *phoneNumber == "") {
		return nil, fmt.Errorf("phone number required for SMS 2FA")
	}
	if method == "totp" && len(totpSecret) == 0 {
		return nil, fmt.Errorf("totp secret required for TOTP 2FA")
	}

	tx, err := s.pg.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	qtx := s.qtx(tx)
	if _, err := qtx.MFALockUser(ctx, userID); err != nil {
		return nil, err
	}

	var currentBackupCodes []string
	if settings, err := qtx.MFASettingsByUser(ctx, userID); err == nil && settings.Enabled {
		currentBackupCodes = settings.BackupCodes
	} else if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return nil, err
	}

	factors, err := qtx.MFAListFactorsByUser(ctx, userID)
	if err != nil {
		return nil, err
	}
	firstFactor := len(factors) == 0
	if mode == FirstFactorOnly && !firstFactor {
		return nil, authkit.ErrTwoFAFactorExists
	}
	for _, factor := range factors {
		if factor.Method == method {
			return nil, authkit.ErrTwoFAFactorExists
		}
	}
	makeDefault = makeDefault || firstFactor

	plaintextCodes := []string(nil)
	if len(currentBackupCodes) == 0 {
		plaintextCodes, currentBackupCodes = generateBackupCodes()
	}

	if makeDefault {
		if err := qtx.MFAClearDefaultFactors(ctx, userID); err != nil {
			return nil, err
		}
	}
	_, err = qtx.MFAInsertFactor(ctx, db.MFAInsertFactorParams{
		UserID:       userID,
		Method:       method,
		PhoneNumber:  phoneNumber,
		TotpSecret:   totpSecret,
		LastTotpStep: lastTOTPStep,
		IsDefault:    makeDefault,
	})
	if err != nil {
		return nil, err
	}

	// Settings holds only the account-level gate + backup codes (#125).
	if err := qtx.MFAUpsertSettings(ctx, db.MFAUpsertSettingsParams{
		UserID:      userID,
		BackupCodes: currentBackupCodes,
	}); err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return plaintextCodes, nil
}

// Disable2FAWithRemovedRoles disables account MFA and removes active user role
// assignments whose catalog role requires MFA.
func (s *Service) Disable2FAWithRemovedRoles(ctx context.Context, userID string) ([]RemovedMFARoleAssignment, error) {
	if s.pg == nil {
		return nil, fmt.Errorf("postgres not configured")
	}

	tx, err := s.pg.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	q := db.ForSchema(tx, s.dbSchema())
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

func (s *Service) Disable2FAFactorWithRemovedRoles(ctx context.Context, userID, factorID string) ([]RemovedMFARoleAssignment, error) {
	if s.pg == nil {
		return nil, fmt.Errorf("postgres not configured")
	}
	if strings.TrimSpace(factorID) == "" {
		return nil, fmt.Errorf("factor id required")
	}
	tx, err := s.pg.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	q := db.ForSchema(tx, s.dbSchema())
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
	removed := []RemovedMFARoleAssignment(nil)
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

func (s *Service) SetDefault2FAFactor(ctx context.Context, userID, factorID string) error {
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
	var selected *db.ProfilesMfaFactor
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
func (s *Service) Get2FASettings(ctx context.Context, userID string) (*TwoFactorSettings, error) {
	if s.pg == nil {
		return nil, fmt.Errorf("postgres not configured")
	}

	row, err := s.q.MFASettingsByUser(ctx, userID)
	if err != nil {
		return nil, err
	}
	// Settings holds only the account gate + backup codes (#125); the displayed
	// method/phone/secret are derived from the default factor below.
	settings := &TwoFactorSettings{
		UserID:      row.UserID,
		Enabled:     row.Enabled,
		BackupCodes: row.BackupCodes,
		CreatedAt:   row.CreatedAt,
		UpdatedAt:   row.UpdatedAt,
	}
	factors, err := s.List2FAFactors(ctx, userID)
	if err == nil {
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
	}
	return settings, nil
}

func (s *Service) List2FAFactors(ctx context.Context, userID string) ([]TwoFactorFactor, error) {
	if s.pg == nil {
		return nil, fmt.Errorf("postgres not configured")
	}
	rows, err := s.q.MFAListFactorsByUser(ctx, userID)
	if err != nil {
		return nil, err
	}
	out := make([]TwoFactorFactor, 0, len(rows))
	for _, row := range rows {
		out = append(out, twoFactorFactorFromFields(row.ID, row.UserID, row.Method, row.PhoneNumber, row.TotpSecret, row.LastTotpStep, row.IsDefault, row.CreatedAt, row.UpdatedAt))
	}
	return out, nil
}

func (s *Service) Require2FAForLoginFactor(ctx context.Context, userID, factorID string) (destination, method string, factor TwoFactorFactor, err error) {
	factor, err = s.twoFactorFactor(ctx, userID, factorID)
	if err != nil {
		return "", "", TwoFactorFactor{}, err
	}
	destination, err = s.send2FACodeForFactor(ctx, userID, "", factor)
	return destination, factor.Method, factor, err
}

func (s *Service) send2FACodeForFactor(ctx context.Context, userID, sessionID string, factor TwoFactorFactor) (string, error) {
	if !factor.Enabled {
		return "", fmt.Errorf("2FA not enabled")
	}
	if factor.Method == "totp" {
		return "authenticator app", nil
	}
	user, err := s.AdminGetUser(ctx, userID)
	if err != nil {
		return "", err
	}

	code := randAlphanumeric(6)
	hash := sha256Hex(code)

	var destination string
	if factor.Method == "email" {
		if user.Email == nil {
			return "", fmt.Errorf("no email address configured")
		}
		destination = *user.Email
	} else { // sms
		if factor.PhoneNumber == nil {
			return "", fmt.Errorf("no phone number configured for SMS 2FA")
		}
		destination = *factor.PhoneNumber
	}

	if !s.useEphemeralStore() {
		return "", fmt.Errorf("ephemeral store not configured")
	}
	if strings.TrimSpace(sessionID) == "" {
		if err := s.storeMFACode(ctx, userID, hash, factor.Method, destination, 10*time.Minute); err != nil {
			return "", err
		}
	} else if err := s.storeMFAStepUpCode(ctx, userID, sessionID, hash, factor.Method, destination, 10*time.Minute); err != nil {
		return "", err
	}

	username := ""
	if user.Username != nil {
		username = *user.Username
	}

	if factor.Method == "email" {
		if s.email != nil {
			sendCtx := s.contextWithUserPreferredLanguage(ctx, userID)
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
			sendCtx := s.contextWithUserPreferredLanguage(ctx, userID)
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

func (s *Service) Require2FAForStepUpMethod(ctx context.Context, userID, sessionID, method string) (destination, selectedMethod string, factor TwoFactorFactor, err error) {
	if strings.TrimSpace(sessionID) == "" {
		return "", "", TwoFactorFactor{}, jwt.ErrTokenInvalidClaims
	}
	factor, err = s.twoFactorFactorByMethod(ctx, userID, method)
	if err != nil {
		return "", "", TwoFactorFactor{}, err
	}
	destination, err = s.send2FACodeForFactor(ctx, userID, sessionID, factor)
	return destination, factor.Method, factor, err
}

func (s *Service) Verify2FAStepUpMethodCode(ctx context.Context, userID, sessionID, method, code string) (bool, error) {
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
func (s *Service) verifyStepUpForFactor(ctx context.Context, userID, sessionID, code string, factor TwoFactorFactor) (bool, error) {
	if factor.Method == "totp" {
		return s.verifyTOTPFactorCode(ctx, factor, code)
	}
	if !s.useEphemeralStore() {
		return false, fmt.Errorf("ephemeral store not configured")
	}
	return s.consumeMFAStepUpCode(ctx, userID, sessionID, sha256Hex(code), factor.Method)
}

// Create2FAChallenge creates a short-lived challenge to prove password verification before 2FA.
func (s *Service) Create2FAChallenge(ctx context.Context, userID string) (string, error) {
	if !s.useEphemeralStore() {
		return "", fmt.Errorf("ephemeral store not configured")
	}
	challenge := RandB64(32)
	hash := sha256Hex(challenge)
	if err := s.storeMFAChallenge(ctx, userID, hash, 10*time.Minute); err != nil {
		return "", err
	}
	return challenge, nil
}

// Verify2FAChallenge verifies the challenge created during the password step.
func (s *Service) Verify2FAChallenge(ctx context.Context, userID, challenge string) (bool, error) {
	if strings.TrimSpace(challenge) == "" {
		return false, nil
	}
	if !s.useEphemeralStore() {
		return false, fmt.Errorf("ephemeral store not configured")
	}
	stored, ok, err := s.getMFAChallenge(ctx, userID)
	if err != nil || !ok {
		return false, err
	}
	return SecretEqual(stored, sha256Hex(challenge)), nil
}

// Clear2FAChallenge removes the stored challenge after successful 2FA verification.
func (s *Service) Clear2FAChallenge(ctx context.Context, userID string) error {
	if !s.useEphemeralStore() {
		return fmt.Errorf("ephemeral store not configured")
	}
	return s.deleteMFAChallenge(ctx, userID)
}

// Verify2FACode verifies a 2FA code entered by the user during login.
// Returns true if code is valid, false otherwise.
func (s *Service) Verify2FACode(ctx context.Context, userID, code string) (bool, error) {
	return s.Verify2FAFactorCode(ctx, userID, "", code)
}

func (s *Service) Verify2FAFactorCode(ctx context.Context, userID, factorID, code string) (bool, error) {
	factor, err := s.twoFactorFactor(ctx, userID, factorID)
	if err != nil {
		return false, err
	}
	if factor.Method == "totp" {
		return s.verifyTOTPFactorCode(ctx, factor, code)
	}

	hash := sha256Hex(code)

	if s.useEphemeralStore() {
		return s.consumeMFACode(ctx, userID, hash)
	}
	return false, fmt.Errorf("ephemeral store not configured")
}

func (s *Service) verifyTOTPFactorCode(ctx context.Context, factor TwoFactorFactor, code string) (bool, error) {
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
	rows, err := s.q.MFAConsumeFactorTOTPStep(ctx, db.MFAConsumeFactorTOTPStepParams{ID: factor.ID, UserID: factor.UserID, Step: &step})
	return rows > 0, err
}

// VerifyBackupCode verifies a 2FA backup code for account recovery.
// On success, removes the used backup code from the user's backup codes.
func (s *Service) VerifyBackupCode(ctx context.Context, userID, backupCode string) (bool, error) {
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
	rows, err := s.q.MFAConsumeBackupCode(ctx, db.MFAConsumeBackupCodeParams{CodeHash: hash, UserID: userID})
	if err != nil {
		return false, err
	}
	return rows == 1, nil
}

// RegenerateBackupCodes generates new backup codes for a user (invalidating old ones).
// Returns the plaintext codes (caller must show these to user ONCE).
func (s *Service) RegenerateBackupCodes(ctx context.Context, userID string) ([]string, error) {
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

func (s *Service) twoFactorFactor(ctx context.Context, userID, factorID string) (TwoFactorFactor, error) {
	if s.pg == nil {
		return TwoFactorFactor{}, fmt.Errorf("postgres not configured")
	}
	factors, err := s.List2FAFactors(ctx, userID)
	if err != nil {
		return TwoFactorFactor{}, err
	}
	if len(factors) == 0 {
		settings, err := s.Get2FASettings(ctx, userID)
		if err != nil || !settings.Enabled || len(settings.Factors) == 0 {
			return TwoFactorFactor{}, fmt.Errorf("2FA not enabled")
		}
		factors = settings.Factors
	}
	if strings.TrimSpace(factorID) != "" {
		for _, factor := range factors {
			if factor.ID == factorID {
				return factor, nil
			}
		}
		return TwoFactorFactor{}, pgx.ErrNoRows
	}
	for _, factor := range factors {
		if factor.IsDefault {
			return factor, nil
		}
	}
	return factors[0], nil
}

func (s *Service) twoFactorFactorByMethod(ctx context.Context, userID, method string) (TwoFactorFactor, error) {
	method = strings.ToLower(strings.TrimSpace(method))
	if method == "" {
		return s.twoFactorFactor(ctx, userID, "")
	}
	if method != "email" && method != "sms" && method != "totp" {
		return TwoFactorFactor{}, fmt.Errorf("invalid 2FA method: must be 'email', 'sms', or 'totp'")
	}
	factors, err := s.List2FAFactors(ctx, userID)
	if err != nil {
		return TwoFactorFactor{}, err
	}
	if len(factors) == 0 {
		settings, err := s.Get2FASettings(ctx, userID)
		if err != nil || !settings.Enabled || len(settings.Factors) == 0 {
			return TwoFactorFactor{}, fmt.Errorf("2FA not enabled")
		}
		factors = settings.Factors
	}
	for _, factor := range factors {
		if factor.Enabled && strings.EqualFold(factor.Method, method) {
			return factor, nil
		}
	}
	return TwoFactorFactor{}, pgx.ErrNoRows
}

func twoFactorFactorFromFields(id, userID, method string, phone *string, secret []byte, step *int64, isDefault bool, createdAt, updatedAt time.Time) TwoFactorFactor {
	return TwoFactorFactor{
		ID:           id,
		UserID:       userID,
		Method:       method,
		PhoneNumber:  phone,
		TOTPSecret:   secret,
		LastTOTPStep: step,
		IsDefault:    isDefault,
		Enabled:      true, // #125: a factor row existing IS the enabled state
		CreatedAt:    createdAt,
		UpdatedAt:    updatedAt,
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
