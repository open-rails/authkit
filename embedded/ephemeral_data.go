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
	UserID   string `json:"user_id"`
	Phone    string `json:"phone"`
	Purpose  string `json:"purpose"`
	CodeHash string `json:"code_hash"`
	LinkHash string `json:"link_hash,omitempty"`
}

type emailVerifyData struct {
	UserID   string  `json:"user_id"`
	Email    *string `json:"email,omitempty"`
	CodeHash string  `json:"code_hash"`
	LinkHash string  `json:"link_hash,omitempty"`
}

type passwordResetData struct {
	UserID string `json:"user_id"`
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
func (s *Service) consumeLink(ctx context.Context, linkKey string) (string, bool) {
	key, ok, err := s.ephemConsumeString(ctx, linkKey)
	return key, err == nil && ok && key != ""
}

// DeletePendingRegistrationByEmail removes a pending email registration for the
// given email, if one exists. No-op when none exists.
func (s *Service) DeletePendingRegistrationByEmail(ctx context.Context, email string) error {
	if !s.useEphemeralStore() {
		return nil
	}
	s.deletePendingChangeByTarget(ctx, KindRegisterEmail, email)
	return nil
}

// DeletePendingPhoneRegistrationByPhone removes a pending phone registration for
// the given phone, if one exists. No-op when none exists.
func (s *Service) DeletePendingPhoneRegistrationByPhone(ctx context.Context, phone string) error {
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
func (s *Service) storePhoneVerification(ctx context.Context, purpose, phone, userID, codeHash, linkHash string, ttl time.Duration) error {
	if ttl <= 0 {
		ttl = defaultPhoneVerificationTTL
	}
	purpose = normalizePhoneVerificationPurpose(purpose)
	phone = NormalizePhone(phone)
	key := phoneVerificationKey(purpose, phone)
	s.deletePhoneVerification(ctx, key)
	data := phoneVerificationData{UserID: userID, Phone: phone, Purpose: purpose, CodeHash: codeHash, LinkHash: linkHash}
	if err := s.ephemSetJSON(ctx, key, data, ttl); err != nil {
		return err
	}
	if linkHash != "" {
		return s.ephemSetString(ctx, keyPhoneVerifyLink+linkHash, key, ttl)
	}
	return nil
}

func (s *Service) deletePhoneVerification(ctx context.Context, key string) {
	var data phoneVerificationData
	if ok, _ := s.ephemGetJSON(ctx, key, &data); ok && data.LinkHash != "" {
		_ = s.ephemDel(ctx, keyPhoneVerifyLink+data.LinkHash)
	}
	_ = s.ephemDel(ctx, key)
}

// consumePhoneVerification checks a typed code against the record issued for
// (purpose, phone). A wrong code leaves the record intact; the per-phone attempt
// cap bounds guessing.
func (s *Service) consumePhoneVerification(ctx context.Context, purpose, phone, codeHash string) (string, error) {
	key := phoneVerificationKey(purpose, phone)
	var data phoneVerificationData
	ok, err := s.ephemGetJSON(ctx, key, &data)
	if err != nil {
		return "", err
	}
	if !ok || !SecretEqual(data.CodeHash, codeHash) {
		return "", jwt.ErrTokenUnverifiable
	}
	s.deletePhoneVerification(ctx, key)
	return data.UserID, nil
}

// consumePhoneVerificationByLink redeems the 256-bit link token: the pointer is
// consumed atomically (single-use), then the record it names must still carry
// that link hash. Returns (userID, phone).
func (s *Service) consumePhoneVerificationByLink(ctx context.Context, purpose, linkHash string) (string, string, error) {
	key, ok := s.consumeLink(ctx, keyPhoneVerifyLink+linkHash)
	if !ok {
		return "", "", jwt.ErrTokenUnverifiable
	}
	var data phoneVerificationData
	ok, err := s.ephemGetJSON(ctx, key, &data)
	if err != nil {
		return "", "", err
	}
	if !ok || data.Purpose != normalizePhoneVerificationPurpose(purpose) || !SecretEqual(data.LinkHash, linkHash) {
		return "", "", jwt.ErrTokenUnverifiable
	}
	_ = s.ephemDel(ctx, key)
	return data.UserID, data.Phone, nil
}

// storeEmailVerification issues one verification record per user, superseding
// any outstanding one.
func (s *Service) storeEmailVerification(ctx context.Context, userID string, email *string, codeHash, linkHash string, ttl time.Duration) error {
	if ttl <= 0 {
		ttl = defaultEmailVerificationTTL
	}
	key := keyEmailVerify + userID
	s.deleteEmailVerification(ctx, userID)
	data := emailVerifyData{UserID: userID, Email: email, CodeHash: codeHash, LinkHash: linkHash}
	if err := s.ephemSetJSON(ctx, key, data, ttl); err != nil {
		return err
	}
	return s.ephemSetString(ctx, keyEmailVerifyLink+linkHash, key, ttl)
}

func (s *Service) deleteEmailVerification(ctx context.Context, userID string) {
	key := keyEmailVerify + userID
	var data emailVerifyData
	if ok, _ := s.ephemGetJSON(ctx, key, &data); ok && data.LinkHash != "" {
		_ = s.ephemDel(ctx, keyEmailVerifyLink+data.LinkHash)
	}
	_ = s.ephemDel(ctx, key)
}

// consumeEmailVerificationCode checks a typed code against the user's outstanding
// record; the record must have been issued for the supplied address. A wrong
// code leaves the record intact; the per-email attempt cap bounds guessing.
func (s *Service) consumeEmailVerificationCode(ctx context.Context, userID, email, codeHash string) error {
	var data emailVerifyData
	ok, err := s.ephemGetJSON(ctx, keyEmailVerify+userID, &data)
	if err != nil {
		return err
	}
	if !ok || !SecretEqual(data.CodeHash, codeHash) {
		return jwt.ErrTokenUnverifiable
	}
	if data.Email == nil || !strings.EqualFold(NormalizeEmail(*data.Email), email) {
		return jwt.ErrTokenInvalidClaims
	}
	s.deleteEmailVerification(ctx, userID)
	return nil
}

// consumeEmailVerificationByLink redeems the 256-bit link token (single-use
// pointer consume, then the record must still carry that link hash).
func (s *Service) consumeEmailVerificationByLink(ctx context.Context, linkHash string) (*emailVerifyToken, error) {
	key, ok := s.consumeLink(ctx, keyEmailVerifyLink+linkHash)
	if !ok {
		return nil, jwt.ErrTokenUnverifiable
	}
	var data emailVerifyData
	ok, err := s.ephemGetJSON(ctx, key, &data)
	if err != nil {
		return nil, err
	}
	if !ok || !SecretEqual(data.LinkHash, linkHash) {
		return nil, jwt.ErrTokenUnverifiable
	}
	_ = s.ephemDel(ctx, key)
	return &emailVerifyToken{UserID: data.UserID, Email: data.Email}, nil
}

// RecordFailedEmailVerifyCode increments the per-email failed-attempt counter for
// the typed email-verification code. After maxEmailVerifyCodeAttempts failures it
// invalidates every outstanding code/pending-registration for that address so the
// short numeric code cannot be brute-forced within its TTL (AK security audit F1).
// No-op without an ephemeral store.
func (s *Service) RecordFailedEmailVerifyCode(ctx context.Context, email string) {
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
func (s *Service) recordFailedAttempt(ctx context.Context, key string, ttl time.Duration, max int64) bool {
	n, err := s.ephemIncr(ctx, key, ttl)
	if err != nil || n >= max {
		_ = s.ephemDel(ctx, key)
		return true
	}
	return false
}

// ClearEmailVerifyCodeAttempts resets the per-email failed-attempt counter after a
// successful confirmation.
func (s *Service) ClearEmailVerifyCodeAttempts(ctx context.Context, email string) {
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
func (s *Service) invalidateEmailVerifyCodes(ctx context.Context, email string) {
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
func (s *Service) RecordFailedPhoneVerifyCode(ctx context.Context, phone string) {
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
func (s *Service) ClearPhoneVerifyCodeAttempts(ctx context.Context, phone string) {
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
func (s *Service) invalidatePhoneVerifyCodes(ctx context.Context, phone string) {
	phone = NormalizePhone(strings.TrimSpace(phone))
	if phone == "" {
		return
	}
	s.deletePendingChangeByTarget(ctx, KindRegisterPhone, phone)
	s.deletePhoneVerification(ctx, phoneVerificationKey("verify_phone", phone))
}

func (s *Service) storePasswordReset(ctx context.Context, tokenHash, userID string, ttl time.Duration) error {
	data := passwordResetData{UserID: userID}
	return s.ephemSetJSON(ctx, keyPasswordReset+tokenHash, data, ttl)
}

func (s *Service) consumePasswordReset(ctx context.Context, tokenHash string) (string, error) {
	var data passwordResetData
	// Single-use: the token hash IS the key, so presenting it consumes it. Consume
	// atomically (same class as AK2-PK-001) so a reset token can't be redeemed
	// twice by concurrent requests racing a Get+Del.
	ok, err := s.ephemConsumeJSON(ctx, keyPasswordReset+tokenHash, &data)
	if err != nil {
		return "", err
	}
	if !ok {
		return "", jwt.ErrTokenUnverifiable
	}
	return data.UserID, nil
}

func (s *Service) storeMFACode(ctx context.Context, userID, codeHash, method, destination string, ttl time.Duration) error {
	data := twoFactorData{CodeHash: codeHash, Method: method, Destination: destination}
	return s.ephemSetJSON(ctx, keyTwoFactor+userID, data, ttl)
}

func (s *Service) consumeMFACode(ctx context.Context, userID, codeHash string) (bool, error) {
	var data twoFactorData
	// Atomic single-use consume (#199 F2/plan015): get+del as ONE op so the same
	// code cannot authenticate two concurrent requests racing a Get-then-Del. Same
	// class as the password-reset/passkey consume. Trade-off: a presented code is
	// spent even on hash mismatch (one attempt per issued code — resend to retry),
	// which also bounds online brute force of the short numeric code.
	ok, err := s.ephemConsumeJSON(ctx, keyTwoFactor+userID, &data)
	if err != nil || !ok {
		return false, nil
	}
	if !SecretEqual(data.CodeHash, codeHash) {
		return false, nil
	}
	return true, nil
}

func (s *Service) storeMFAStepUpCode(ctx context.Context, userID, sessionID, codeHash, method, destination string, ttl time.Duration) error {
	data := twoFactorData{CodeHash: codeHash, Method: method, Destination: destination}
	return s.ephemSetJSON(ctx, keyTwoFactorStepUp+userID+":"+sessionID, data, ttl)
}

func (s *Service) consumeMFAStepUpCode(ctx context.Context, userID, sessionID, codeHash, method string) (bool, error) {
	var data twoFactorData
	key := keyTwoFactorStepUp + userID + ":" + sessionID
	// Atomic single-use consume (#199 F2/plan015) — see consumeMFACode.
	ok, err := s.ephemConsumeJSON(ctx, key, &data)
	if err != nil || !ok {
		return false, nil
	}
	if !SecretEqual(data.CodeHash, codeHash) {
		return false, nil
	}
	if method != "" && !strings.EqualFold(strings.TrimSpace(data.Method), strings.TrimSpace(method)) {
		return false, nil
	}
	return true, nil
}

func (s *Service) storeMFAChallenge(ctx context.Context, userID, challengeHash string, ttl time.Duration) error {
	return s.ephemSetString(ctx, keyTwoFactorChallenge+userID, challengeHash, ttl)
}

func (s *Service) getMFAChallenge(ctx context.Context, userID string) (string, bool, error) {
	return s.ephemGetString(ctx, keyTwoFactorChallenge+userID)
}

func (s *Service) deleteMFAChallenge(ctx context.Context, userID string) error {
	return s.ephemDel(ctx, keyTwoFactorChallenge+userID)
}

func (s *Service) storePasskeyCeremony(ctx context.Context, challenge string, data passkeyCeremonyData, ttl time.Duration) error {
	return s.ephemSetJSON(ctx, keyPasskeyCeremony+challenge, data, ttl)
}

func (s *Service) consumePasskeyCeremony(ctx context.Context, challenge string) (passkeyCeremonyData, error) {
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
