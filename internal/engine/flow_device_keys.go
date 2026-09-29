package engine

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	stdlog "log"
	"slices"
	"strings"
	"time"

	jwt "github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/authflow"
	"github.com/open-rails/authkit/internal/contact"
	"github.com/open-rails/authkit/internal/db"
	"github.com/open-rails/authkit/internal/errmodel"
	"github.com/open-rails/authkit/internal/secret"
)

const (
	deviceKeyEnrollmentDomain = "authkit.device-key-enrollment/1"
	deviceKeyLoginDomain      = "authkit.device-key-login/1"
	deviceKeyChallengeTTL     = 10 * time.Minute
	deviceKeyLabelMaxLength   = 128
	deviceKeyMaxCodeAttempts  = 5

	keyDeviceKeyEnrollment        = "device-key:enrollment:"
	keyDeviceKeyEnrollmentAttempt = "device-key:enrollment-attempt:"
	keyDeviceKeyLogin             = "device-key:login:"
)

var errDeviceKeyInvalid = jwt.ErrTokenUnverifiable

func (s *Engine) deviceKeysEnabled() error {
	if s == nil || !s.cfg.DeviceKeys.Enabled {
		return iam.ErrDeviceKeysDisabled
	}
	return nil
}

type deviceKeyEnrollment struct {
	Email     string    `json:"email"`
	PublicKey string    `json:"public_key"`
	Label     string    `json:"label,omitempty"`
	CodeHash  string    `json:"code_hash"`
	Challenge string    `json:"challenge"`
	ExpiresAt time.Time `json:"expires_at"`
}

type deviceKeyLogin struct {
	DeviceKeyID string    `json:"device_key_id"`
	UserID      string    `json:"user_id,omitempty"`
	PublicKey   string    `json:"public_key,omitempty"`
	Challenge   string    `json:"challenge"`
	ExpiresAt   time.Time `json:"expires_at"`
}

func decodeDeviceKey(raw string) ([]byte, error) {
	raw = strings.TrimSpace(raw)
	decoded, err := base64.RawURLEncoding.DecodeString(raw)
	if err != nil || len(decoded) != ed25519.PublicKeySize || base64.RawURLEncoding.EncodeToString(decoded) != raw {
		return nil, errDeviceKeyInvalid
	}
	return decoded, nil
}

func decodeDeviceSignature(raw string) ([]byte, error) {
	raw = strings.TrimSpace(raw)
	decoded, err := base64.RawURLEncoding.DecodeString(raw)
	if err != nil || len(decoded) != ed25519.SignatureSize || base64.RawURLEncoding.EncodeToString(decoded) != raw {
		return nil, errDeviceKeyInvalid
	}
	return decoded, nil
}

func deviceKeySigningMessage(domain, encodedChallenge string) ([]byte, error) {
	challenge, err := base64.RawURLEncoding.DecodeString(encodedChallenge)
	if err != nil || len(challenge) != 32 || base64.RawURLEncoding.EncodeToString(challenge) != encodedChallenge {
		return nil, errDeviceKeyInvalid
	}
	message := make([]byte, 0, len(domain)+1+len(challenge))
	message = append(message, domain...)
	message = append(message, 0)
	message = append(message, challenge...)
	return message, nil
}

// BeginDeviceKeyEnrollment sends an email proof and records the proposed key.
func (s *Engine) BeginDeviceKeyEnrollment(ctx context.Context, email, publicKey, label string) (authflow.DeviceKeyChallenge, error) {
	if err := s.deviceKeysEnabled(); err != nil {
		return authflow.DeviceKeyChallenge{}, err
	}
	if s.pg == nil {
		return authflow.DeviceKeyChallenge{}, s.requirePG()
	}
	if !s.useEphemeralStore() {
		return authflow.DeviceKeyChallenge{}, jwt.ErrTokenUnverifiable
	}
	email = contact.NormalizeEmail(email)
	if err := contact.ValidateEmail(email); err != nil {
		return authflow.DeviceKeyChallenge{}, err
	}
	decodedPublicKey, err := decodeDeviceKey(publicKey)
	if err != nil {
		return authflow.DeviceKeyChallenge{}, err
	}
	publicKey = base64.RawURLEncoding.EncodeToString(decodedPublicKey)
	label = strings.TrimSpace(label)
	if len(label) > deviceKeyLabelMaxLength {
		return authflow.DeviceKeyChallenge{}, errDeviceKeyInvalid
	}
	if s.email == nil {
		return authflow.DeviceKeyChallenge{}, errmodel.ErrEmailUnavailable
	}

	now := time.Now().UTC()
	result := authflow.DeviceKeyChallenge{ID: secret.RandB64(32), Challenge: secret.RandB64(32), ExpiresAt: now.Add(deviceKeyChallengeTTL)}
	code := randAlphanumeric(6)
	record := deviceKeyEnrollment{
		Email: email, PublicKey: publicKey, Label: label,
		CodeHash: sha256Hex(code), Challenge: result.Challenge, ExpiresAt: result.ExpiresAt,
	}
	if err := s.ephemSetJSON(ctx, keyDeviceKeyEnrollment+result.ID, record, deviceKeyChallengeTTL); err != nil {
		return authflow.DeviceKeyChallenge{}, err
	}
	message := iam.VerificationMessage{Code: code, Purpose: "device_key_enrollment"}
	if err := message.Validate(); err != nil {
		_ = s.ephemDel(ctx, keyDeviceKeyEnrollment+result.ID)
		return authflow.DeviceKeyChallenge{}, err
	}
	if err := s.withSendTimeout(ctx, func(sendCtx context.Context) error {
		return s.email.SendVerification(sendCtx, email, "", message)
	}); err != nil {
		_ = s.ephemDel(ctx, keyDeviceKeyEnrollment+result.ID)
		return authflow.DeviceKeyChallenge{}, emailDeliveryError(err)
	}
	return result, nil
}

// FinishDeviceKeyEnrollment consumes both proofs, enrolls the key, and mints no
// refresh session. An existing account with a usable second factor must also
// present one independent of the emailed code (secondFactor: a TOTP or SMS
// code, or a backup code) — email possession alone never enrolls a standing
// credential on an MFA-protected account (#293, P1). A revoked key, or one
// bound to another account, is refused before any second factor is asked for,
// and a backup code is spent only by the enrollment that commits (R4).
func (s *Engine) FinishDeviceKeyEnrollment(ctx context.Context, enrollmentID, code, signature, secondFactor string) (authflow.DeviceKeyAuthResult, error) {
	if err := s.deviceKeysEnabled(); err != nil {
		return authflow.DeviceKeyAuthResult{}, err
	}
	enrollmentID = strings.TrimSpace(enrollmentID)
	var record deviceKeyEnrollment
	ok, err := s.ephemGetJSON(ctx, keyDeviceKeyEnrollment+enrollmentID, &record)
	if err != nil || !ok {
		return authflow.DeviceKeyAuthResult{}, errDeviceKeyInvalid
	}
	if !secret.Equal(record.CodeHash, sha256Hex(strings.TrimSpace(code))) {
		return authflow.DeviceKeyAuthResult{}, errDeviceKeyInvalid
	}
	publicKey, err := decodeDeviceKey(record.PublicKey)
	if err != nil {
		return authflow.DeviceKeyAuthResult{}, errDeviceKeyInvalid
	}
	sig, err := decodeDeviceSignature(signature)
	if err != nil {
		return authflow.DeviceKeyAuthResult{}, errDeviceKeyInvalid
	}
	message, err := deviceKeySigningMessage(deviceKeyEnrollmentDomain, record.Challenge)
	if err != nil || !ed25519.Verify(publicKey, message, sig) {
		return authflow.DeviceKeyAuthResult{}, errDeviceKeyInvalid
	}

	user, err := s.getUserByEmail(ctx, record.Email)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return authflow.DeviceKeyAuthResult{}, err
	}
	owner := ""
	if user != nil {
		owner = user.ID
	}
	if err := deviceKeyEnrollable(ctx, s.pg, publicKey, owner); err != nil {
		return authflow.DeviceKeyAuthResult{}, err
	}
	mfaProof, backupCode := false, ""
	if user != nil {
		if err := s.ensureUserAccess(ctx, user); err != nil {
			return authflow.DeviceKeyAuthResult{}, err
		}
		status, err := s.mfaStatus(ctx, user.ID)
		if err != nil {
			return authflow.DeviceKeyAuthResult{}, err
		}
		if s.TwoFactorEnabled() && status.Satisfied {
			factors, backupHashes, err := s.deviceKeySecondFactors(ctx, user.ID)
			if err != nil {
				return authflow.DeviceKeyAuthResult{}, err
			}
			if strings.TrimSpace(secondFactor) == "" {
				method, err := s.challengeDeviceKeySecondFactor(ctx, user, enrollmentID, factors, len(backupHashes) > 0)
				if err != nil {
					return authflow.DeviceKeyAuthResult{}, err
				}
				return authflow.DeviceKeyAuthResult{}, &authflow.DeviceKeySecondFactorRequired{Method: method}
			}
			if backupCode, mfaProof = s.verifyDeviceKeySecondFactor(ctx, user.ID, enrollmentID, factors, backupHashes, strings.TrimSpace(secondFactor)); !mfaProof {
				return authflow.DeviceKeyAuthResult{}, errDeviceKeyInvalid
			}
		}
		// The session MFA gate every login passes: a holder of an MFA-required
		// role without a second factor, or any account when enrollment is
		// mandatory, enrolls one before it may hold a standing credential.
		if err := s.requireSessionMFAStateOn(ctx, s.pg, user.ID, deviceKeyEnrollmentMethods(mfaProof), status, nil); err != nil {
			return authflow.DeviceKeyAuthResult{}, err
		}
	} else if s.TwoFactorEnabled() && s.requireMFAEnrollment() {
		return authflow.DeviceKeyAuthResult{}, iam.ErrTwoFAEnrollmentRequired
	}

	var consumed deviceKeyEnrollment
	ok, err = s.ephemConsumeJSON(ctx, keyDeviceKeyEnrollment+enrollmentID, &consumed)
	if err != nil || !ok || consumed.Challenge != record.Challenge || consumed.CodeHash != record.CodeHash || consumed.PublicKey != record.PublicKey {
		return authflow.DeviceKeyAuthResult{}, errDeviceKeyInvalid
	}
	_ = s.ephemDel(ctx, keyDeviceKeyEnrollmentAttempt+enrollmentID)

	deviceKey, userID, created, err := s.enrollDeviceKey(ctx, record, publicKey, mfaProof, backupCode)
	if err != nil {
		return authflow.DeviceKeyAuthResult{}, err
	}
	if user != nil && created {
		s.notifyDeviceKeyEnrolled(ctx, user, deviceKey)
	}
	accessToken, expiresAt, err := s.mintDeviceKeyAccessToken(ctx, userID, deviceKey.ID, deviceKeyEnrollmentMethods(mfaProof))
	if err != nil {
		return authflow.DeviceKeyAuthResult{}, err
	}
	return authflow.DeviceKeyAuthResult{AccessToken: accessToken, ExpiresAt: expiresAt, DeviceKey: deviceKey}, nil
}

// deviceKeyEnrollmentMethods is what an enrollment proves: the key, the
// emailed code and, on an account with a second factor, that factor.
func deviceKeyEnrollmentMethods(mfaProof bool) []string {
	if mfaProof {
		return []string{"device_key", "email", "otp", "mfa"}
	}
	return []string{"device_key", "email"}
}

// deviceKeyEnrollmentProof is the first factor an enrollment presents: the
// emailed code. The email factor reads the same mailbox, so it never counts
// as a second factor here, as at login (independentFactor).
var deviceKeyEnrollmentProof = loginProof{Input: loginSessionInput{AuthMethods: []string{"email"}}}

// deviceKeySecondFactors are the account's usable factors independent of the
// emailed enrollment code, default first, and the hashes of its backup codes.
func (s *Engine) deviceKeySecondFactors(ctx context.Context, userID string) ([]authflow.TwoFactorFactor, []string, error) {
	settings, err := s.Get2FASettings(ctx, userID)
	if err != nil {
		return nil, nil, err
	}
	return s.loginFactors(deviceKeyEnrollmentProof, settings), settings.BackupCodes, nil
}

// deviceKeyEnrollable refuses a public key that is revoked or bound to an
// account other than owner ("" for an account the enrollment would create).
func deviceKeyEnrollable(ctx context.Context, q db.DBTX, publicKey []byte, owner string) error {
	var holder string
	var revoked bool
	err := q.QueryRow(ctx, `SELECT user_id::text, revoked_at IS NOT NULL FROM user_device_keys WHERE public_key=$1`, publicKey).Scan(&holder, &revoked)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	if revoked || holder != owner {
		return errDeviceKeyInvalid
	}
	return nil
}

// challengeDeviceKeySecondFactor names the proof the retry carries in
// code_2fa, sending the SMS code first. An account whose only factor is email
// proves with a backup code, or enrolls an independent factor.
func (s *Engine) challengeDeviceKeySecondFactor(ctx context.Context, user *userRecord, enrollmentID string, factors []authflow.TwoFactorFactor, backupCodes bool) (string, error) {
	if len(factors) == 0 {
		if backupCodes {
			return "backup_code", nil
		}
		return "", iam.ErrTwoFAEnrollmentRequired
	}
	if factors[0].Method == "sms" {
		if _, err := s.send2FACodeForUser(ctx, user, deviceKeyCodeScope(enrollmentID), factors[0]); err != nil {
			return "", err
		}
	}
	return factors[0].Method, nil
}

// verifyDeviceKeySecondFactor accepts a TOTP code or the SMS code sent for
// this enrollment, spending it, or one of the account's backup codes, which it
// returns unspent for enrollDeviceKey to spend; never the email factor's.
func (s *Engine) verifyDeviceKeySecondFactor(ctx context.Context, userID, enrollmentID string, factors []authflow.TwoFactorFactor, backupHashes []string, code string) (backupCode string, ok bool) {
	for _, f := range factors {
		var ok bool
		var err error
		switch f.Method {
		case "totp":
			ok, err = s.verifyTOTPFactorCode(ctx, f, code)
		case "sms":
			ok, err = s.consumeMFAStepUpCode(ctx, userID, deviceKeyCodeScope(enrollmentID), sha256Hex(code), "sms")
		}
		if err == nil && ok {
			return "", true
		}
	}
	if slices.Contains(backupHashes, sha256Hex(code)) {
		return code, true
	}
	return "", false
}

// deviceKeyCodeScope binds an SMS code to one enrollment ceremony.
func deviceKeyCodeScope(enrollmentID string) string { return "device-key:" + sha256Hex(enrollmentID) }

// notifyDeviceKeyEnrolled is best-effort: the key is already enrolled, so a
// delivery failure is logged rather than reported as a failed enrollment.
func (s *Engine) notifyDeviceKeyEnrolled(ctx context.Context, u *userRecord, key authflow.DeviceKey) {
	if s.email == nil || u.Email == nil {
		return
	}
	username := ""
	if u.Username != nil {
		username = *u.Username
	}
	sendCtx := s.contextWithUserPreferredLanguage(ctx, u.ID)
	if err := s.withSendTimeout(sendCtx, func(c context.Context) error {
		return s.email.SendDeviceKeyEnrolled(c, *u.Email, username, iam.DeviceKeyNotice{Label: key.Label, CreatedAt: key.CreatedAt})
	}); err != nil {
		stdlog.Printf("[authkit/security] device-key enrollment notice failed for user %s: %v", u.ID, err)
	}
}

// enrollDeviceKey inserts the key (created=true) or returns the identical key
// already enrolled on the same account (created=false). A second-factor proof
// binds the key to it (mfa_proven_at), including a re-enrollment of a key
// enrolled before the account had one. A backupCode proof is spent in the same
// transaction.
func (s *Engine) enrollDeviceKey(ctx context.Context, record deviceKeyEnrollment, publicKey []byte, mfaProof bool, backupCode string) (authflow.DeviceKey, string, bool, error) {
	user, err := s.getUserByEmail(ctx, record.Email)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return authflow.DeviceKey{}, "", false, err
	}
	if user != nil {
		if err := s.ensureUserAccess(ctx, user); err != nil {
			return authflow.DeviceKey{}, "", false, err
		}
	} else {
		allowed, err := s.registrationAllowedForEmail(ctx, record.Email)
		if err != nil {
			return authflow.DeviceKey{}, "", false, err
		}
		if !allowed {
			return authflow.DeviceKey{}, "", false, errmodel.ErrRegistrationDisabled
		}
	}

	tx, err := s.pg.Begin(ctx)
	if err != nil {
		return authflow.DeviceKey{}, "", false, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	q := tx
	if user == nil {
		userID, err := newUUIDV7String()
		if err != nil {
			return authflow.DeviceKey{}, "", false, err
		}
		_, err = q.Exec(ctx, `INSERT INTO users (id, email, email_verified)
VALUES ($1, $2, true) ON CONFLICT DO NOTHING`, userID, record.Email)
		if err != nil {
			return authflow.DeviceKey{}, "", false, err
		}
	}
	var userID string
	if err := q.QueryRow(ctx, `SELECT id FROM users WHERE email=$1`, record.Email).Scan(&userID); err != nil {
		return authflow.DeviceKey{}, "", false, err
	}
	// The emailed enrollment code proves the address (ak#393).
	proven, err := s.retirePreProofCredentials(ctx, tx, userID, nil)
	if err != nil {
		return authflow.DeviceKey{}, "", false, err
	}
	if _, err := q.Exec(ctx, `UPDATE users SET email_verified=true, updated_at=now() WHERE id=$1`, userID); err != nil {
		return authflow.DeviceKey{}, "", false, err
	}

	var existing authflow.DeviceKey
	var existingUserID string
	var revokedAt *time.Time
	err = q.QueryRow(ctx, `SELECT id, user_id, COALESCE(label, ''), created_at, last_used_at, revoked_at
FROM user_device_keys WHERE public_key=$1`, publicKey).
		Scan(&existing.ID, &existingUserID, &existing.Label, &existing.CreatedAt, &existing.LastUsedAt, &revokedAt)
	found := err == nil
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return authflow.DeviceKey{}, "", false, err
	}
	if found && (existingUserID != userID || revokedAt != nil) {
		return authflow.DeviceKey{}, "", false, errDeviceKeyInvalid
	}
	if backupCode != "" {
		spent, err := s.verifyBackupCode(ctx, s.qtx(tx), userID, backupCode)
		if err != nil {
			return authflow.DeviceKey{}, "", false, err
		}
		if !spent {
			return authflow.DeviceKey{}, "", false, errDeviceKeyInvalid
		}
	}
	if found {
		if mfaProof {
			if _, err := q.Exec(ctx, `UPDATE user_device_keys SET mfa_proven_at=now() WHERE id=$1`, existing.ID); err != nil {
				return authflow.DeviceKey{}, "", false, err
			}
		}
		if err := tx.Commit(ctx); err != nil {
			return authflow.DeviceKey{}, "", false, err
		}
		s.logRevokedSessions(ctx, userID, proven, string(authflow.SessionRevokeReasonContactProven))
		return existing, userID, false, nil
	}

	var label *string
	if record.Label != "" {
		label = &record.Label
	}
	if err := q.QueryRow(ctx, `INSERT INTO user_device_keys (user_id, public_key, label, mfa_proven_at)
VALUES ($1, $2, $3, CASE WHEN $4 THEN now() END) RETURNING id, COALESCE(label, ''), created_at, last_used_at`, userID, publicKey, label, mfaProof).
		Scan(&existing.ID, &existing.Label, &existing.CreatedAt, &existing.LastUsedAt); err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			return authflow.DeviceKey{}, "", false, errDeviceKeyInvalid
		}
		return authflow.DeviceKey{}, "", false, err
	}
	if err := tx.Commit(ctx); err != nil {
		return authflow.DeviceKey{}, "", false, err
	}
	s.logRevokedSessions(ctx, userID, proven, string(authflow.SessionRevokeReasonContactProven))
	return existing, userID, true, nil
}

// RecordFailedDeviceKeyEnrollment bounds online guessing without consuming a valid ceremony on one typo.
func (s *Engine) RecordFailedDeviceKeyEnrollment(ctx context.Context, enrollmentID string) {
	enrollmentID = strings.TrimSpace(enrollmentID)
	if enrollmentID == "" || !s.useEphemeralStore() {
		return
	}
	if s.recordFailedAttempt(ctx, keyDeviceKeyEnrollmentAttempt+enrollmentID, deviceKeyChallengeTTL, deviceKeyMaxCodeAttempts) {
		_ = s.ephemDel(ctx, keyDeviceKeyEnrollment+enrollmentID)
	}
}

// BeginDeviceKeyLogin returns an indistinguishable challenge for active, revoked, and unknown ids.
func (s *Engine) BeginDeviceKeyLogin(ctx context.Context, deviceKeyID string) (authflow.DeviceKeyChallenge, error) {
	if err := s.deviceKeysEnabled(); err != nil {
		return authflow.DeviceKeyChallenge{}, err
	}
	if s.pg == nil {
		return authflow.DeviceKeyChallenge{}, s.requirePG()
	}
	deviceKeyID = strings.TrimSpace(deviceKeyID)
	if _, err := uuid.Parse(deviceKeyID); err != nil {
		return authflow.DeviceKeyChallenge{}, errDeviceKeyInvalid
	}
	if !s.useEphemeralStore() {
		return authflow.DeviceKeyChallenge{}, jwt.ErrTokenUnverifiable
	}
	record := deviceKeyLogin{DeviceKeyID: deviceKeyID}
	row := s.pg.QueryRow(ctx, `SELECT user_id, public_key
FROM user_device_keys WHERE id=$1 AND revoked_at IS NULL`, deviceKeyID)
	var publicKey []byte
	if err := row.Scan(&record.UserID, &publicKey); err == nil {
		record.PublicKey = base64.RawURLEncoding.EncodeToString(publicKey)
	} else if !errors.Is(err, pgx.ErrNoRows) {
		return authflow.DeviceKeyChallenge{}, err
	}
	now := time.Now().UTC()
	result := authflow.DeviceKeyChallenge{ID: secret.RandB64(32), Challenge: secret.RandB64(32), ExpiresAt: now.Add(deviceKeyChallengeTTL)}
	record.Challenge, record.ExpiresAt = result.Challenge, result.ExpiresAt
	if err := s.ephemSetJSON(ctx, keyDeviceKeyLogin+result.ID, record, deviceKeyChallengeTTL); err != nil {
		return authflow.DeviceKeyChallenge{}, err
	}
	return result, nil
}

// FinishDeviceKeyLogin atomically consumes a challenge and issues only a short access token.
func (s *Engine) FinishDeviceKeyLogin(ctx context.Context, challengeID, signature string) (authflow.DeviceKeyAuthResult, error) {
	if err := s.deviceKeysEnabled(); err != nil {
		return authflow.DeviceKeyAuthResult{}, err
	}
	var record deviceKeyLogin
	ok, err := s.ephemGetJSON(ctx, keyDeviceKeyLogin+strings.TrimSpace(challengeID), &record)
	if err != nil || !ok || record.UserID == "" || record.PublicKey == "" {
		return authflow.DeviceKeyAuthResult{}, errDeviceKeyInvalid
	}
	publicKey, err := decodeDeviceKey(record.PublicKey)
	if err != nil {
		return authflow.DeviceKeyAuthResult{}, errDeviceKeyInvalid
	}
	sig, err := decodeDeviceSignature(signature)
	if err != nil {
		return authflow.DeviceKeyAuthResult{}, errDeviceKeyInvalid
	}
	message, err := deviceKeySigningMessage(deviceKeyLoginDomain, record.Challenge)
	if err != nil || !ed25519.Verify(publicKey, message, sig) {
		return authflow.DeviceKeyAuthResult{}, errDeviceKeyInvalid
	}
	var consumed deviceKeyLogin
	ok, err = s.ephemConsumeJSON(ctx, keyDeviceKeyLogin+strings.TrimSpace(challengeID), &consumed)
	if err != nil || !ok || consumed.Challenge != record.Challenge || consumed.DeviceKeyID != record.DeviceKeyID {
		return authflow.DeviceKeyAuthResult{}, errDeviceKeyInvalid
	}

	var deviceKey authflow.DeviceKey
	var mfaBound bool
	err = s.pg.QueryRow(ctx, `UPDATE user_device_keys
SET last_used_at=now() WHERE id=$1 AND user_id=$2 AND revoked_at IS NULL
RETURNING id, COALESCE(label, ''), created_at, last_used_at, mfa_proven_at IS NOT NULL`, record.DeviceKeyID, record.UserID).
		Scan(&deviceKey.ID, &deviceKey.Label, &deviceKey.CreatedAt, &deviceKey.LastUsedAt, &mfaBound)
	if err != nil {
		return authflow.DeviceKeyAuthResult{}, errDeviceKeyInvalid
	}
	// A key counts as a second factor only when its enrollment proved one; any
	// other key signs in only where a password alone would.
	methods := []string{"device_key"}
	if mfaBound {
		methods = append(methods, "mfa")
	}
	accessToken, expiresAt, err := s.mintDeviceKeyAccessToken(ctx, record.UserID, deviceKey.ID, methods)
	if err != nil {
		return authflow.DeviceKeyAuthResult{}, err
	}
	return authflow.DeviceKeyAuthResult{AccessToken: accessToken, ExpiresAt: expiresAt, DeviceKey: deviceKey}, nil
}

// ListDeviceKeys returns the user's machine credentials after proving that the
// device which minted the caller's token is still active.
func (s *Engine) ListDeviceKeys(ctx context.Context, userID, currentID string) ([]authflow.DeviceKey, error) {
	q := s.pg
	var active bool
	if err := q.QueryRow(ctx, `SELECT EXISTS (
		SELECT 1 FROM user_device_keys
		WHERE id=$1 AND user_id=$2 AND revoked_at IS NULL
	)`, currentID, userID).Scan(&active); err != nil || !active {
		return nil, errDeviceKeyInvalid
	}
	rows, err := q.Query(ctx, `SELECT id, COALESCE(label, ''), created_at, last_used_at, revoked_at
		FROM user_device_keys WHERE user_id=$1 ORDER BY created_at, id`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	keys := make([]authflow.DeviceKey, 0)
	for rows.Next() {
		var key authflow.DeviceKey
		if err := rows.Scan(&key.ID, &key.Label, &key.CreatedAt, &key.LastUsedAt, &key.RevokedAt); err != nil {
			return nil, err
		}
		keys = append(keys, key)
	}
	return keys, rows.Err()
}

// ActiveDeviceKeys returns the user's unrevoked device public keys in
// enrollment order.
func (s *Engine) ActiveDeviceKeys(ctx context.Context, userID string) ([]ed25519.PublicKey, error) {
	if err := s.deviceKeysEnabled(); err != nil {
		return nil, err
	}
	rows, err := s.pg.Query(ctx, `SELECT public_key FROM user_device_keys
		WHERE user_id=$1 AND revoked_at IS NULL ORDER BY created_at, id`, userID)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowTo[ed25519.PublicKey])
}

// RevokeDeviceKey idempotently revokes one key owned by the caller. The
// token's own key is checked live in the same transaction first, so a revoked
// machine cannot use the remainder of its access-token lifetime to revoke a
// replacement machine.
func (s *Engine) RevokeDeviceKey(ctx context.Context, userID, currentID, targetID string) error {
	tx, err := s.pg.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	q := tx
	if targetID == currentID {
		result, err := q.Exec(ctx, `UPDATE user_device_keys SET revoked_at=COALESCE(revoked_at, now())
			WHERE id=$1 AND user_id=$2`, currentID, userID)
		if err != nil {
			return err
		}
		if result.RowsAffected() != 1 {
			return errDeviceKeyInvalid
		}
		return tx.Commit(ctx)
	}
	var active bool
	if err := q.QueryRow(ctx, `SELECT EXISTS (
		SELECT 1 FROM user_device_keys
		WHERE id=$1 AND user_id=$2 AND revoked_at IS NULL FOR UPDATE
	)`, currentID, userID).Scan(&active); err != nil || !active {
		return errDeviceKeyInvalid
	}
	if _, err := q.Exec(ctx, `UPDATE user_device_keys SET revoked_at=COALESCE(revoked_at, now())
		WHERE id=$1 AND user_id=$2`, targetID, userID); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// revokeAllDeviceKeys revokes every live key of userID on q and returns the
// count (ban, soft delete, account emergency revoke).
func (s *Engine) revokeAllDeviceKeys(ctx context.Context, q db.DBTX, userID string) (int64, error) {
	tag, err := q.Exec(ctx, `UPDATE user_device_keys SET revoked_at=now()
		WHERE user_id=$1 AND revoked_at IS NULL`, userID)
	return tag.RowsAffected(), err
}

// RevokeOtherDeviceKeys atomically revokes every key except the live key that
// minted the caller's email-proven token.
func (s *Engine) RevokeOtherDeviceKeys(ctx context.Context, userID, currentID string) error {
	tx, err := s.pg.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	q := tx
	var active bool
	if err := q.QueryRow(ctx, `SELECT EXISTS (
		SELECT 1 FROM user_device_keys
		WHERE id=$1 AND user_id=$2 AND revoked_at IS NULL FOR UPDATE
	)`, currentID, userID).Scan(&active); err != nil || !active {
		return errDeviceKeyInvalid
	}
	if _, err := q.Exec(ctx, `UPDATE user_device_keys SET revoked_at=now()
		WHERE user_id=$1 AND id<>$2 AND revoked_at IS NULL`, userID, currentID); err != nil {
		return err
	}
	return tx.Commit(ctx)
}
