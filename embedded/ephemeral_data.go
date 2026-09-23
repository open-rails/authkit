package embedded

import (
	"context"
	"strings"
	"time"

	jwt "github.com/golang-jwt/jwt/v5"
)

const (
	defaultEmailVerificationTTL = time.Hour
	defaultPhoneVerificationTTL = 15 * time.Minute

	// Wrong typed-code guesses allowed per address before the outstanding code is
	// invalidated, so a 6-digit code cannot be brute-forced within its TTL.
	maxEmailVerifyCodeAttempts = 5
	keyEmailVerifyCodeAttempts = "email_verify:attempts:"
	maxPhoneVerifyCodeAttempts = 5
	keyPhoneVerifyCodeAttempts = "phone_verify:attempts:"
	maxTwoFactorCodeAttempts   = 5
	keyTwoFactorCodeAttempts   = "2fa:attempts:" // +<code record key>
	twoFactorCodeTTL           = 10 * time.Minute

	// A short code is never part of a key (#301): a verification record lives
	// under the identity it was issued for and carries its code hash inside. Only
	// 256-bit link tokens get a global pointer (link hash -> record key).
	keyPhoneVerify        = "phone_verify:rec:"  // +<purpose>:<phone>
	keyPhoneVerifyLink    = "phone_verify:link:" // +<linkHash> -> record key
	keyEmailVerify        = "email_verify:user:" // +<userID>
	keyEmailVerifyLink    = "email_verify:link:" // +<linkHash> -> record key
	keyPasswordReset      = "password_reset:token:"
	keyTwoFactor          = "2fa:code:"
	keyTwoFactorStepUp    = "2fa:step-up:"
	keyTwoFactorChallenge = "2fa:challenge:"
	keyPasskeyCeremony    = "passkey:"
)

type phoneVerificationData struct {
	ID       string `json:"id"`
	Version  int64  `json:"version"`
	UserID   string `json:"user_id"`
	Phone    string `json:"phone"`
	Purpose  string `json:"purpose"`
	CodeHash string `json:"code_hash"`
	LinkHash string `json:"link_hash,omitempty"`
}

type emailVerifyData struct {
	ID       string  `json:"id"`
	Version  int64   `json:"version"`
	UserID   string  `json:"user_id"`
	Email    *string `json:"email,omitempty"`
	CodeHash string  `json:"code_hash"`
	LinkHash string  `json:"link_hash,omitempty"`
}

type passwordResetData struct {
	UserID  string `json:"user_id"`
	Version int64  `json:"version"`
	Channel string `json:"channel"`
	Contact string `json:"contact"`
}

type twoFactorData struct {
	CodeHash    string `json:"code_hash"`
	Method      string `json:"method"`
	Destination string `json:"destination"`
}

type passkeyCeremonyData struct {
	Purpose string `json:"purpose"`
	UserID  string `json:"user_id,omitempty"`
	Session []byte `json:"session"`
}

// consumeLink atomically resolves and burns a link-token pointer, returning the
// record key it pointed at.
func (s *engine) consumeLink(ctx context.Context, linkKey string) (string, bool) {
	key, ok, err := s.ephemConsumeString(ctx, linkKey)
	return key, err == nil && ok && key != ""
}

// DeletePendingRegistrationByEmail removes a pending email registration for the
// given email, if one exists. No-op when none exists.
func (s *engine) DeletePendingRegistrationByEmail(ctx context.Context, email string) error {
	if !s.useEphemeralStore() {
		return nil
	}
	s.deletePendingChangeByTarget(ctx, KindRegisterEmail, email)
	return nil
}

// DeletePendingPhoneRegistrationByPhone removes a pending phone registration for
// the given phone, if one exists. No-op when none exists.
func (s *engine) DeletePendingPhoneRegistrationByPhone(ctx context.Context, phone string) error {
	if !s.useEphemeralStore() {
		return nil
	}
	s.deletePendingChangeByTarget(ctx, KindRegisterPhone, phone)
	return nil
}

func normalizePhoneVerificationPurpose(purpose string) string {
	purpose = strings.TrimSpace(purpose)
	if purpose == "" {
		return "verify_phone"
	}
	return purpose
}

func phoneVerificationKey(purpose, phone string) string {
	return keyPhoneVerify + normalizePhoneVerificationPurpose(purpose) + ":" + NormalizePhone(phone)
}

// storePhoneVerification issues one verification record per (purpose, phone),
// superseding any outstanding one. linkHash may be empty for code-only purposes.
func (s *engine) storePhoneVerification(ctx context.Context, purpose, phone, userID, codeHash, linkHash string, ttl time.Duration) error {
	if err := s.requirePG(); err != nil {
		return err
	}
	if ttl <= 0 {
		ttl = defaultPhoneVerificationTTL
	}
	purpose = normalizePhoneVerificationPurpose(purpose)
	phone = NormalizePhone(phone)
	key := phoneVerificationKey(purpose, phone)
	s.deletePhoneVerification(ctx, key)
	version, err := s.q.UserCredentialVersion(ctx, userID)
	if err != nil {
		return err
	}
	data := phoneVerificationData{ID: RandB64(16), Version: version.CredentialVersion, UserID: userID, Phone: phone, Purpose: purpose, CodeHash: codeHash, LinkHash: linkHash}
	if err := s.ephemSetJSON(ctx, key, data, ttl); err != nil {
		return err
	}
	if linkHash != "" {
		return s.ephemSetString(ctx, keyPhoneVerifyLink+linkHash, key, ttl)
	}
	return nil
}

func (s *engine) deletePhoneVerification(ctx context.Context, key string) {
	var data phoneVerificationData
	raw, ok, _ := s.ephemReadJSON(ctx, key, &data)
	if ok && s.claimProof(ctx, key, raw) == nil && data.LinkHash != "" {
		_ = s.ephemDel(ctx, keyPhoneVerifyLink+data.LinkHash)
	}
}

// consumePhoneVerification checks a typed code against the record issued for
// (purpose, phone). A wrong code leaves the record intact; the per-phone attempt
// cap bounds guessing.
func (s *engine) consumePhoneVerification(ctx context.Context, purpose, phone, codeHash string) (string, error) {
	key := phoneVerificationKey(purpose, phone)
	var data phoneVerificationData
	raw, ok, err := s.ephemReadJSON(ctx, key, &data)
	if err != nil {
		return "", err
	}
	if !ok || data.ID == "" || data.Version <= 0 || !SecretEqual(data.CodeHash, codeHash) {
		return "", jwt.ErrTokenUnverifiable
	}
	if err := s.claimProof(ctx, key, raw); err != nil {
		return "", err
	}
	if data.LinkHash != "" {
		_ = s.ephemDel(ctx, keyPhoneVerifyLink+data.LinkHash)
	}
	return data.UserID, nil
}

// storeEmailVerification issues one verification record per user, superseding
// any outstanding one.
func (s *engine) storeEmailVerification(ctx context.Context, userID string, email *string, codeHash, linkHash string, ttl time.Duration) error {
	if err := s.requirePG(); err != nil {
		return err
	}
	if ttl <= 0 {
		ttl = defaultEmailVerificationTTL
	}
	key := keyEmailVerify + userID
	s.deleteEmailVerification(ctx, userID)
	version, err := s.q.UserCredentialVersion(ctx, userID)
	if err != nil {
		return err
	}
	data := emailVerifyData{ID: RandB64(16), Version: version.CredentialVersion, UserID: userID, Email: email, CodeHash: codeHash, LinkHash: linkHash}
	if err := s.ephemSetJSON(ctx, key, data, ttl); err != nil {
		return err
	}
	return s.ephemSetString(ctx, keyEmailVerifyLink+linkHash, key, ttl)
}

func (s *engine) deleteEmailVerification(ctx context.Context, userID string) {
	key := keyEmailVerify + userID
	var data emailVerifyData
	raw, ok, _ := s.ephemReadJSON(ctx, key, &data)
	if ok && s.claimProof(ctx, key, raw) == nil && data.LinkHash != "" {
		_ = s.ephemDel(ctx, keyEmailVerifyLink+data.LinkHash)
	}
}

// RecordFailedEmailVerifyCode increments the per-email failed-attempt counter for
// the typed email-verification code. After maxEmailVerifyCodeAttempts failures it
// invalidates every outstanding code/pending-registration for that address so the
// short numeric code cannot be brute-forced within its TTL (AK security audit F1).
// No-op without an ephemeral store.
func (s *engine) RecordFailedEmailVerifyCode(ctx context.Context, email string) {
	if !s.useEphemeralStore() {
		return
	}
	email = NormalizeEmail(strings.TrimSpace(email))
	if email == "" {
		return
	}
	if s.recordFailedAttempt(ctx, keyEmailVerifyCodeAttempts+email, defaultEmailVerificationTTL, maxEmailVerifyCodeAttempts) {
		s.invalidateEmailVerifyCodes(ctx, email)
	}
}

// recordFailedAttempt bumps a per-identifier wrong-guess counter atomically and
// reports whether the cap is reached, clearing the counter so a re-issued code
// starts fresh. A store error counts as reached (fail closed): a guess that
// cannot be counted must not keep the code alive.
func (s *engine) recordFailedAttempt(ctx context.Context, key string, ttl time.Duration, max int64) bool {
	n, err := s.ephemIncr(ctx, key, ttl)
	if err != nil || n >= max {
		_ = s.ephemDel(ctx, key)
		return true
	}
	return false
}

// ClearEmailVerifyCodeAttempts resets the per-email failed-attempt counter after a
// successful confirmation.
func (s *engine) ClearEmailVerifyCodeAttempts(ctx context.Context, email string) {
	if !s.useEphemeralStore() {
		return
	}
	email = NormalizeEmail(strings.TrimSpace(email))
	if email == "" {
		return
	}
	_ = s.ephemDel(ctx, keyEmailVerifyCodeAttempts+email)
}

// invalidateEmailVerifyCodes deletes the outstanding pending registration and
// existing-user verification record for the address once the attempt cap is hit.
func (s *engine) invalidateEmailVerifyCodes(ctx context.Context, email string) {
	email = NormalizeEmail(strings.TrimSpace(email))
	if email == "" {
		return
	}
	s.deletePendingChangeByTarget(ctx, KindRegisterEmail, email)
	if s.pg != nil {
		if u, err := s.getUserByEmail(ctx, email); err == nil && u != nil {
			s.deleteEmailVerification(ctx, u.ID)
		}
	}
}

// RecordFailedPhoneVerifyCode is the phone twin of RecordFailedEmailVerifyCode:
// after maxPhoneVerifyCodeAttempts wrong guesses the outstanding code(s) for the
// number are invalidated. No-op without an ephemeral store.
func (s *engine) RecordFailedPhoneVerifyCode(ctx context.Context, phone string) {
	if !s.useEphemeralStore() {
		return
	}
	phone = NormalizePhone(strings.TrimSpace(phone))
	if phone == "" {
		return
	}
	if s.recordFailedAttempt(ctx, keyPhoneVerifyCodeAttempts+phone, defaultPhoneVerificationTTL, maxPhoneVerifyCodeAttempts) {
		s.invalidatePhoneVerifyCodes(ctx, phone)
	}
}

// ClearPhoneVerifyCodeAttempts resets the per-phone failed-attempt counter after a
// successful confirmation.
func (s *engine) ClearPhoneVerifyCodeAttempts(ctx context.Context, phone string) {
	if !s.useEphemeralStore() {
		return
	}
	phone = NormalizePhone(strings.TrimSpace(phone))
	if phone == "" {
		return
	}
	_ = s.ephemDel(ctx, keyPhoneVerifyCodeAttempts+phone)
}

// invalidatePhoneVerifyCodes deletes the outstanding codes for a number when the
// attempt cap is hit: the pending phone registration and the existing-user
// "verify_phone" record (the two unauthenticated confirm paths).
func (s *engine) invalidatePhoneVerifyCodes(ctx context.Context, phone string) {
	phone = NormalizePhone(strings.TrimSpace(phone))
	if phone == "" {
		return
	}
	s.deletePendingChangeByTarget(ctx, KindRegisterPhone, phone)
	s.deletePhoneVerification(ctx, phoneVerificationKey("verify_phone", phone))
}

func (s *engine) storePasswordReset(ctx context.Context, tokenHash, userID, channel, contact string, ttl time.Duration) error {
	row, err := s.q.UserCredentialVersion(ctx, userID)
	if err != nil {
		return err
	}
	actual := row.Email
	if channel == "sms" {
		actual = row.PhoneNumber
	}
	if channel == "email" {
		contact = strings.ToLower(strings.TrimSpace(contact))
	}
	if (channel != "email" && channel != "sms") || actual == nil || *actual != contact {
		return jwt.ErrTokenInvalidClaims
	}
	data := passwordResetData{UserID: userID, Version: row.CredentialVersion, Channel: channel, Contact: contact}
	return s.ephemSetJSON(ctx, keyPasswordReset+tokenHash, data, ttl)
}

func (s *engine) consumePasswordReset(ctx context.Context, tokenHash string) (passwordResetData, error) {
	var data passwordResetData
	ok, err := s.ephemConsumeJSON(ctx, keyPasswordReset+tokenHash, &data)
	if err != nil {
		return data, err
	}
	if !ok || data.Version <= 0 {
		return data, jwt.ErrTokenUnverifiable
	}
	return data, nil
}

func (s *engine) storeMFACode(ctx context.Context, userID, codeHash, method, destination string) error {
	return s.storeTwoFactorCode(ctx, keyTwoFactor+userID, twoFactorData{CodeHash: codeHash, Method: method, Destination: destination})
}

func (s *engine) consumeMFACode(ctx context.Context, userID, codeHash string) (bool, error) {
	return s.consumeTwoFactorCode(ctx, keyTwoFactor+userID, codeHash, "")
}

func (s *engine) storeMFAStepUpCode(ctx context.Context, userID, sessionID, codeHash, method, destination string) error {
	return s.storeTwoFactorCode(ctx, keyTwoFactorStepUp+userID+":"+sessionID, twoFactorData{CodeHash: codeHash, Method: method, Destination: destination})
}

func (s *engine) consumeMFAStepUpCode(ctx context.Context, userID, sessionID, codeHash, method string) (bool, error) {
	return s.consumeTwoFactorCode(ctx, keyTwoFactorStepUp+userID+":"+sessionID, codeHash, method)
}

// storeTwoFactorCode issues a fresh code with a fresh wrong-guess budget.
func (s *engine) storeTwoFactorCode(ctx context.Context, key string, data twoFactorData) error {
	if err := s.ephemSetJSON(ctx, key, data, twoFactorCodeTTL); err != nil {
		return err
	}
	return s.ephemDel(ctx, keyTwoFactorCodeAttempts+key)
}

// consumeTwoFactorCode spends the stored code only on a match (#387). The
// compare-and-delete on the exact record read gives concurrent correct
// submissions one winner and fails if a resend replaced the code meanwhile. A
// wrong guess keeps the code; the maxTwoFactorCodeAttempts-th burns it. No live
// code (expired, never sent, spent, or burned by this miss) is ErrTwoFACodeExpired.
func (s *engine) consumeTwoFactorCode(ctx context.Context, key, codeHash, method string) (bool, error) {
	var data twoFactorData
	raw, ok, err := s.ephemReadJSON(ctx, key, &data)
	if err != nil {
		return false, err
	}
	if !ok {
		return false, ErrTwoFACodeExpired
	}
	match := SecretEqual(data.CodeHash, codeHash) &&
		(method == "" || strings.EqualFold(strings.TrimSpace(data.Method), strings.TrimSpace(method)))
	if !match {
		if s.recordFailedAttempt(ctx, keyTwoFactorCodeAttempts+key, twoFactorCodeTTL, maxTwoFactorCodeAttempts) {
			_, _ = s.ephemeralStore.CompareAndConsume(ctx, key, raw)
			return false, ErrTwoFACodeExpired
		}
		return false, nil
	}
	claimed, err := s.ephemeralStore.CompareAndConsume(ctx, key, raw)
	if err != nil {
		return false, err
	}
	if !claimed {
		return false, ErrTwoFACodeExpired
	}
	_ = s.ephemDel(ctx, keyTwoFactorCodeAttempts+key)
	return true, nil
}

func (s *engine) storePasskeyCeremony(ctx context.Context, challenge string, data passkeyCeremonyData, ttl time.Duration) error {
	return s.ephemSetJSON(ctx, keyPasskeyCeremony+challenge, data, ttl)
}

func (s *engine) consumePasskeyCeremony(ctx context.Context, challenge string) (passkeyCeremonyData, error) {
	var data passkeyCeremonyData
	// AK2-PK-001: the WebAuthn challenge is single-use — consume it ATOMICALLY so
	// two concurrent finish requests presenting the same challenge cannot both
	// succeed (assertion/registration replay). A Get+Del here is not single-use
	// under concurrency. The synced-passkey signCount=0 case means the counter is
	// no backstop, so this atomicity is the replay defense.
	ok, err := s.ephemConsumeJSON(ctx, keyPasskeyCeremony+challenge, &data)
	if err != nil || !ok {
		return data, jwt.ErrTokenUnverifiable
	}
	return data, nil
}
