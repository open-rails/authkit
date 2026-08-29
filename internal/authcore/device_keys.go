package authcore

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"strconv"
	"strings"
	"time"

	jwt "github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/open-rails/authkit/internal/db"
)

const (
	deviceKeyEnrollmentDomain = "authkit.device-key-enrollment/1"
	deviceKeyLoginDomain      = "authkit.device-key-login/1"
	deviceKeyChallengeTTL     = 10 * time.Minute
	deviceKeyLabelMaxLength   = 128
	deviceKeyMaxCodeAttempts  = 5

	keyDeviceKeyEnrollment        = "auth:device-key:enrollment:"
	keyDeviceKeyEnrollmentAttempt = "auth:device-key:enrollment-attempt:"
	keyDeviceKeyLogin             = "auth:device-key:login:"
)

var errDeviceKeyInvalid = jwt.ErrTokenUnverifiable

// DeviceKey is the public projection of one native-client credential.
type DeviceKey struct {
	ID         string     `json:"id"`
	Label      string     `json:"label,omitempty"`
	CreatedAt  time.Time  `json:"created_at"`
	LastUsedAt *time.Time `json:"last_used_at,omitempty"`
}

type DeviceKeyChallenge struct {
	ID        string
	Challenge string
	ExpiresAt time.Time
}

type DeviceKeyAuthResult struct {
	AccessToken string
	ExpiresAt   time.Time
	DeviceKey   DeviceKey
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
func (s *Service) BeginDeviceKeyEnrollment(ctx context.Context, email, publicKey, label string) (DeviceKeyChallenge, error) {
	if s == nil || s.pg == nil {
		return DeviceKeyChallenge{}, s.requirePG()
	}
	if !s.useEphemeralStore() {
		return DeviceKeyChallenge{}, jwt.ErrTokenUnverifiable
	}
	email = NormalizeEmail(email)
	if err := ValidateEmail(email); err != nil {
		return DeviceKeyChallenge{}, err
	}
	decodedPublicKey, err := decodeDeviceKey(publicKey)
	if err != nil {
		return DeviceKeyChallenge{}, err
	}
	publicKey = base64.RawURLEncoding.EncodeToString(decodedPublicKey)
	label = strings.TrimSpace(label)
	if len(label) > deviceKeyLabelMaxLength {
		return DeviceKeyChallenge{}, errDeviceKeyInvalid
	}
	if s.email == nil {
		return DeviceKeyChallenge{}, ErrEmailSenderUnavailable
	}

	now := time.Now().UTC()
	result := DeviceKeyChallenge{ID: randB64(32), Challenge: randB64(32), ExpiresAt: now.Add(deviceKeyChallengeTTL)}
	code := randAlphanumeric(6)
	record := deviceKeyEnrollment{
		Email: email, PublicKey: publicKey, Label: label,
		CodeHash: sha256Hex(code), Challenge: result.Challenge, ExpiresAt: result.ExpiresAt,
	}
	if err := s.ephemSetJSON(ctx, keyDeviceKeyEnrollment+result.ID, record, deviceKeyChallengeTTL); err != nil {
		return DeviceKeyChallenge{}, err
	}
	message := VerificationMessage{Code: code, Purpose: "device_key_enrollment"}
	if err := message.Validate(); err != nil {
		_ = s.ephemDel(ctx, keyDeviceKeyEnrollment+result.ID)
		return DeviceKeyChallenge{}, err
	}
	if err := s.withSendTimeout(ctx, func(sendCtx context.Context) error {
		return s.email.SendVerification(sendCtx, email, "", message)
	}); err != nil {
		_ = s.ephemDel(ctx, keyDeviceKeyEnrollment+result.ID)
		return DeviceKeyChallenge{}, emailDeliveryError(err)
	}
	return result, nil
}

// FinishDeviceKeyEnrollment consumes both proofs, enrolls the key, and mints no refresh session.
func (s *Service) FinishDeviceKeyEnrollment(ctx context.Context, enrollmentID, code, signature string) (DeviceKeyAuthResult, error) {
	var record deviceKeyEnrollment
	ok, err := s.ephemGetJSON(ctx, keyDeviceKeyEnrollment+strings.TrimSpace(enrollmentID), &record)
	if err != nil || !ok {
		return DeviceKeyAuthResult{}, errDeviceKeyInvalid
	}
	if !secretHashEqual(record.CodeHash, sha256Hex(strings.TrimSpace(code))) {
		return DeviceKeyAuthResult{}, errDeviceKeyInvalid
	}
	publicKey, err := decodeDeviceKey(record.PublicKey)
	if err != nil {
		return DeviceKeyAuthResult{}, errDeviceKeyInvalid
	}
	sig, err := decodeDeviceSignature(signature)
	if err != nil {
		return DeviceKeyAuthResult{}, errDeviceKeyInvalid
	}
	message, err := deviceKeySigningMessage(deviceKeyEnrollmentDomain, record.Challenge)
	if err != nil || !ed25519.Verify(publicKey, message, sig) {
		return DeviceKeyAuthResult{}, errDeviceKeyInvalid
	}
	var consumed deviceKeyEnrollment
	ok, err = s.ephemConsumeJSON(ctx, keyDeviceKeyEnrollment+strings.TrimSpace(enrollmentID), &consumed)
	if err != nil || !ok || consumed.Challenge != record.Challenge || consumed.CodeHash != record.CodeHash || consumed.PublicKey != record.PublicKey {
		return DeviceKeyAuthResult{}, errDeviceKeyInvalid
	}
	_ = s.ephemDel(ctx, keyDeviceKeyEnrollmentAttempt+strings.TrimSpace(enrollmentID))

	deviceKey, userID, err := s.enrollDeviceKey(ctx, record, publicKey)
	if err != nil {
		return DeviceKeyAuthResult{}, err
	}
	accessToken, expiresAt, err := s.mintDeviceKeyAccessToken(ctx, userID, deviceKey.ID)
	if err != nil {
		return DeviceKeyAuthResult{}, err
	}
	return DeviceKeyAuthResult{AccessToken: accessToken, ExpiresAt: expiresAt, DeviceKey: deviceKey}, nil
}

func (s *Service) enrollDeviceKey(ctx context.Context, record deviceKeyEnrollment, publicKey []byte) (DeviceKey, string, error) {
	user, err := s.getUserByEmail(ctx, record.Email)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return DeviceKey{}, "", err
	}
	if user != nil {
		if err := s.ensureUserAccess(ctx, user); err != nil {
			return DeviceKey{}, "", err
		}
	} else {
		allowed, err := s.registrationAllowedForEmail(ctx, record.Email)
		if err != nil {
			return DeviceKey{}, "", err
		}
		if !allowed {
			return DeviceKey{}, "", ErrRegistrationDisabled
		}
	}

	tx, err := s.pg.Begin(ctx)
	if err != nil {
		return DeviceKey{}, "", err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	q := db.ForSchema(tx, s.dbSchema())
	if user == nil {
		userID, err := newUUIDV7String()
		if err != nil {
			return DeviceKey{}, "", err
		}
		_, err = q.Exec(ctx, `INSERT INTO profiles.users (id, email, email_verified)
VALUES ($1, $2, true) ON CONFLICT DO NOTHING`, userID, record.Email)
		if err != nil {
			return DeviceKey{}, "", err
		}
	}
	var userID string
	if err := q.QueryRow(ctx, `SELECT id FROM profiles.users WHERE email=$1`, record.Email).Scan(&userID); err != nil {
		return DeviceKey{}, "", err
	}
	if _, err := q.Exec(ctx, `UPDATE profiles.users SET email_verified=true, updated_at=now() WHERE id=$1`, userID); err != nil {
		return DeviceKey{}, "", err
	}

	var existing DeviceKey
	var existingUserID string
	var revokedAt *time.Time
	err = q.QueryRow(ctx, `SELECT id, user_id, COALESCE(label, ''), created_at, last_used_at, revoked_at
FROM profiles.user_device_keys WHERE public_key=$1`, publicKey).
		Scan(&existing.ID, &existingUserID, &existing.Label, &existing.CreatedAt, &existing.LastUsedAt, &revokedAt)
	if err == nil {
		if existingUserID != userID || revokedAt != nil {
			return DeviceKey{}, "", errDeviceKeyInvalid
		}
		if err := tx.Commit(ctx); err != nil {
			return DeviceKey{}, "", err
		}
		return existing, userID, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return DeviceKey{}, "", err
	}

	var label *string
	if record.Label != "" {
		label = &record.Label
	}
	if err := q.QueryRow(ctx, `INSERT INTO profiles.user_device_keys (user_id, public_key, label)
VALUES ($1, $2, $3) RETURNING id, COALESCE(label, ''), created_at, last_used_at`, userID, publicKey, label).
		Scan(&existing.ID, &existing.Label, &existing.CreatedAt, &existing.LastUsedAt); err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			return DeviceKey{}, "", errDeviceKeyInvalid
		}
		return DeviceKey{}, "", err
	}
	if err := tx.Commit(ctx); err != nil {
		return DeviceKey{}, "", err
	}
	return existing, userID, nil
}

// RecordFailedDeviceKeyEnrollment bounds online guessing without consuming a valid ceremony on one typo.
func (s *Service) RecordFailedDeviceKeyEnrollment(ctx context.Context, enrollmentID string) {
	enrollmentID = strings.TrimSpace(enrollmentID)
	if enrollmentID == "" || !s.useEphemeralStore() {
		return
	}
	key := keyDeviceKeyEnrollmentAttempt + enrollmentID
	n := 0
	if value, ok, _ := s.ephemGetString(ctx, key); ok {
		n, _ = strconv.Atoi(value)
	}
	n++
	if n >= deviceKeyMaxCodeAttempts {
		_ = s.ephemDel(ctx, keyDeviceKeyEnrollment+enrollmentID)
		_ = s.ephemDel(ctx, key)
		return
	}
	_ = s.ephemSetString(ctx, key, strconv.Itoa(n), deviceKeyChallengeTTL)
}

// BeginDeviceKeyLogin returns an indistinguishable challenge for active, revoked, and unknown ids.
func (s *Service) BeginDeviceKeyLogin(ctx context.Context, deviceKeyID string) (DeviceKeyChallenge, error) {
	if s == nil || s.pg == nil {
		return DeviceKeyChallenge{}, s.requirePG()
	}
	deviceKeyID = strings.TrimSpace(deviceKeyID)
	if _, err := uuid.Parse(deviceKeyID); err != nil {
		return DeviceKeyChallenge{}, errDeviceKeyInvalid
	}
	if !s.useEphemeralStore() {
		return DeviceKeyChallenge{}, jwt.ErrTokenUnverifiable
	}
	record := deviceKeyLogin{DeviceKeyID: deviceKeyID}
	row := db.ForSchema(s.pg, s.dbSchema()).QueryRow(ctx, `SELECT user_id, public_key
FROM profiles.user_device_keys WHERE id=$1 AND revoked_at IS NULL`, deviceKeyID)
	var publicKey []byte
	if err := row.Scan(&record.UserID, &publicKey); err == nil {
		record.PublicKey = base64.RawURLEncoding.EncodeToString(publicKey)
	} else if !errors.Is(err, pgx.ErrNoRows) {
		return DeviceKeyChallenge{}, err
	}
	now := time.Now().UTC()
	result := DeviceKeyChallenge{ID: randB64(32), Challenge: randB64(32), ExpiresAt: now.Add(deviceKeyChallengeTTL)}
	record.Challenge, record.ExpiresAt = result.Challenge, result.ExpiresAt
	if err := s.ephemSetJSON(ctx, keyDeviceKeyLogin+result.ID, record, deviceKeyChallengeTTL); err != nil {
		return DeviceKeyChallenge{}, err
	}
	return result, nil
}

// FinishDeviceKeyLogin atomically consumes a challenge and issues only a short access token.
func (s *Service) FinishDeviceKeyLogin(ctx context.Context, challengeID, signature string) (DeviceKeyAuthResult, error) {
	var record deviceKeyLogin
	ok, err := s.ephemGetJSON(ctx, keyDeviceKeyLogin+strings.TrimSpace(challengeID), &record)
	if err != nil || !ok || record.UserID == "" || record.PublicKey == "" {
		return DeviceKeyAuthResult{}, errDeviceKeyInvalid
	}
	publicKey, err := decodeDeviceKey(record.PublicKey)
	if err != nil {
		return DeviceKeyAuthResult{}, errDeviceKeyInvalid
	}
	sig, err := decodeDeviceSignature(signature)
	if err != nil {
		return DeviceKeyAuthResult{}, errDeviceKeyInvalid
	}
	message, err := deviceKeySigningMessage(deviceKeyLoginDomain, record.Challenge)
	if err != nil || !ed25519.Verify(publicKey, message, sig) {
		return DeviceKeyAuthResult{}, errDeviceKeyInvalid
	}
	var consumed deviceKeyLogin
	ok, err = s.ephemConsumeJSON(ctx, keyDeviceKeyLogin+strings.TrimSpace(challengeID), &consumed)
	if err != nil || !ok || consumed.Challenge != record.Challenge || consumed.DeviceKeyID != record.DeviceKeyID {
		return DeviceKeyAuthResult{}, errDeviceKeyInvalid
	}

	var deviceKey DeviceKey
	err = db.ForSchema(s.pg, s.dbSchema()).QueryRow(ctx, `UPDATE profiles.user_device_keys
SET last_used_at=now() WHERE id=$1 AND user_id=$2 AND revoked_at IS NULL
RETURNING id, COALESCE(label, ''), created_at, last_used_at`, record.DeviceKeyID, record.UserID).
		Scan(&deviceKey.ID, &deviceKey.Label, &deviceKey.CreatedAt, &deviceKey.LastUsedAt)
	if err != nil {
		return DeviceKeyAuthResult{}, errDeviceKeyInvalid
	}
	accessToken, expiresAt, err := s.mintDeviceKeyAccessToken(ctx, record.UserID, deviceKey.ID)
	if err != nil {
		return DeviceKeyAuthResult{}, err
	}
	return DeviceKeyAuthResult{AccessToken: accessToken, ExpiresAt: expiresAt, DeviceKey: deviceKey}, nil
}
