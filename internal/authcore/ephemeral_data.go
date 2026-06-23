package authcore

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	jwt "github.com/golang-jwt/jwt/v5"
)

const (
	defaultEmailVerificationTTL = time.Hour
	defaultPhoneVerificationTTL = 15 * time.Minute

	// maxEmailVerifyCodeAttempts bounds wrong typed-code guesses per email before
	// the outstanding code(s) for that address are invalidated, so a 6-digit code
	// cannot be brute-forced within its TTL (AK security audit F1).
	maxEmailVerifyCodeAttempts = 5
	keyEmailVerifyCodeAttempts = "auth:email_verify:attempts:"

	keyPhoneVerifyToken     = "auth:phone_verify:token:"
	keyPhoneVerifyIndex     = "auth:phone_verify:index:"
	keyEmailVerifyToken     = "auth:email_verify:token:"
	keyEmailVerifyUser      = "auth:email_verify:user:"
	keyPasswordReset        = "auth:password_reset:token:"
	keyPasswordResetSession = "auth:password_reset:session:"
	keyTwoFactor            = "auth:2fa:code:"
	keyTwoFactorReauth      = "auth:2fa:reauth:"
	keyTwoFactorChallenge   = "auth:2fa:challenge:"
	keyPasskeyCeremony      = "auth:passkey:"
)

type phoneVerificationData struct {
	UserID      string   `json:"user_id"`
	Phone       string   `json:"phone"`
	Purpose     string   `json:"purpose"`
	TokenHashes []string `json:"token_hashes,omitempty"`
}

type emailVerifyData struct {
	UserID      string   `json:"user_id"`
	Email       *string  `json:"email,omitempty"`
	TokenHashes []string `json:"token_hashes,omitempty"`
}

type passwordResetData struct {
	UserID string `json:"user_id"`
}

type passwordResetSessionData struct {
	UserID string `json:"user_id"`
}

type twoFactorData struct {
	CodeHash    string `json:"code_hash"`
	Method      string `json:"method"`
	Destination string `json:"destination"`
}

type passkeyCeremonyData struct {
	UserID  string `json:"user_id,omitempty"`
	Session []byte `json:"session"`
}

func normalizeTokenTTLs(tokenTTLs map[string]time.Duration, defaultTTL time.Duration) (map[string]time.Duration, string, time.Duration, error) {
	if defaultTTL <= 0 {
		defaultTTL = 15 * time.Minute
	}

	normalized := make(map[string]time.Duration, len(tokenTTLs))
	canonical := ""
	maxTTL := time.Duration(0)

	for tokenHash, ttl := range tokenTTLs {
		tokenHash = strings.TrimSpace(tokenHash)
		if tokenHash == "" {
			continue
		}
		if ttl <= 0 {
			ttl = defaultTTL
		}
		normalized[tokenHash] = ttl
		if canonical == "" || ttl > maxTTL {
			canonical = tokenHash
			maxTTL = ttl
		}
	}

	if canonical == "" {
		return nil, "", 0, fmt.Errorf("missing token hash")
	}
	return normalized, canonical, maxTTL, nil
}

func uniqueTokenHashes(primary string, hashes []string) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(hashes)+1)

	appendToken := func(v string) {
		v = strings.TrimSpace(v)
		if v == "" {
			return
		}
		if _, ok := seen[v]; ok {
			return
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}

	appendToken(primary)
	for _, h := range hashes {
		appendToken(h)
	}
	return out
}

// DeletePendingRegistrationByEmail removes a pending email registration (and all
// its verification tokens) for the given email, if one exists. Used to abandon a
// pending registration the user explicitly cancelled. No-op when none exists.
func (s *Service) DeletePendingRegistrationByEmail(ctx context.Context, email string) error {
	if !s.useEphemeralStore() {
		return nil
	}
	s.deletePendingChangeByTarget(ctx, KindRegisterEmail, email)
	return nil
}

// DeletePendingPhoneRegistrationByPhone removes a pending phone registration (and
// all its verification tokens) for the given phone, if one exists. No-op when
// none exists.
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

func (s *Service) phoneVerificationIndexKey(purpose, phone string) string {
	purpose = normalizePhoneVerificationPurpose(purpose)
	return keyPhoneVerifyIndex + purpose + ":" + phone
}

func (s *Service) phoneVerificationTokenKey(purpose, tokenHash string) string {
	purpose = normalizePhoneVerificationPurpose(purpose)
	return keyPhoneVerifyToken + purpose + ":" + tokenHash
}

func (s *Service) storePhoneVerification(ctx context.Context, purpose, phone, userID, tokenHash string, ttl time.Duration) error {
	return s.storePhoneVerificationTokens(ctx, purpose, phone, userID, map[string]time.Duration{tokenHash: ttl})
}

func (s *Service) storePhoneVerificationTokens(ctx context.Context, purpose, phone, userID string, tokenTTLs map[string]time.Duration) error {
	purpose = normalizePhoneVerificationPurpose(purpose)
	indexKey := s.phoneVerificationIndexKey(purpose, phone)

	normalizedTTLs, canonicalHash, maxTTL, err := normalizeTokenTTLs(tokenTTLs, defaultPhoneVerificationTTL)
	if err != nil {
		return err
	}

	if old, ok, _ := s.ephemGetString(ctx, indexKey); ok && old != "" {
		s.deletePhoneVerificationByToken(ctx, purpose, old)
	}

	data := phoneVerificationData{
		UserID:      userID,
		Phone:       phone,
		Purpose:     purpose,
		TokenHashes: uniqueTokenHashes(canonicalHash, nil),
	}
	for tokenHash := range normalizedTTLs {
		data.TokenHashes = uniqueTokenHashes(tokenHash, data.TokenHashes)
	}

	for tokenHash, ttl := range normalizedTTLs {
		if err := s.ephemSetJSON(ctx, s.phoneVerificationTokenKey(purpose, tokenHash), data, ttl); err != nil {
			return err
		}
	}
	_ = s.ephemSetString(ctx, indexKey, canonicalHash, maxTTL)
	return nil
}

func (s *Service) deletePhoneVerificationByToken(ctx context.Context, purpose, tokenHash string) {
	purpose = normalizePhoneVerificationPurpose(purpose)
	var data phoneVerificationData
	if ok, _ := s.ephemGetJSON(ctx, s.phoneVerificationTokenKey(purpose, tokenHash), &data); ok {
		for _, h := range uniqueTokenHashes(tokenHash, data.TokenHashes) {
			_ = s.ephemDel(ctx, s.phoneVerificationTokenKey(purpose, h))
		}
		if data.Phone != "" {
			idx := s.phoneVerificationIndexKey(purpose, data.Phone)
			if v, ok, _ := s.ephemGetString(ctx, idx); ok && v != "" {
				for _, h := range uniqueTokenHashes(tokenHash, data.TokenHashes) {
					if v == h {
						_ = s.ephemDel(ctx, idx)
						break
					}
				}
			}
		}
		return
	}
	_ = s.ephemDel(ctx, s.phoneVerificationTokenKey(purpose, tokenHash))
}

func (s *Service) consumePhoneVerification(ctx context.Context, purpose, phone, tokenHash string) (string, error) {
	purpose = normalizePhoneVerificationPurpose(purpose)
	var data phoneVerificationData
	ok, err := s.ephemGetJSON(ctx, s.phoneVerificationTokenKey(purpose, tokenHash), &data)
	if err != nil || !ok {
		return "", jwt.ErrTokenUnverifiable
	}
	if data.Phone != "" && data.Phone != phone {
		return "", jwt.ErrTokenUnverifiable
	}
	userID := data.UserID
	s.deletePhoneVerificationByToken(ctx, purpose, tokenHash)
	return userID, nil
}

func (s *Service) consumePhoneVerificationByToken(ctx context.Context, purpose, tokenHash string) (string, string, error) {
	purpose = normalizePhoneVerificationPurpose(purpose)
	var data phoneVerificationData
	ok, err := s.ephemGetJSON(ctx, s.phoneVerificationTokenKey(purpose, tokenHash), &data)
	if err != nil || !ok {
		return "", "", jwt.ErrTokenUnverifiable
	}
	if data.Purpose != "" && data.Purpose != purpose {
		return "", "", jwt.ErrTokenUnverifiable
	}
	userID := data.UserID
	phone := data.Phone
	s.deletePhoneVerificationByToken(ctx, purpose, tokenHash)
	return userID, phone, nil
}

func (s *Service) storeEmailVerificationTokens(ctx context.Context, userID string, email *string, tokenTTLs map[string]time.Duration) error {
	userKey := keyEmailVerifyUser + userID

	normalizedTTLs, canonicalHash, maxTTL, err := normalizeTokenTTLs(tokenTTLs, defaultEmailVerificationTTL)
	if err != nil {
		return err
	}

	if old, ok, _ := s.ephemGetString(ctx, userKey); ok && old != "" {
		s.deleteEmailVerificationByToken(ctx, old)
	}

	data := emailVerifyData{UserID: userID, Email: email, TokenHashes: uniqueTokenHashes(canonicalHash, nil)}
	for tokenHash := range normalizedTTLs {
		data.TokenHashes = uniqueTokenHashes(tokenHash, data.TokenHashes)
	}

	for tokenHash, ttl := range normalizedTTLs {
		if err := s.ephemSetJSON(ctx, keyEmailVerifyToken+tokenHash, data, ttl); err != nil {
			return err
		}
	}
	_ = s.ephemSetString(ctx, userKey, canonicalHash, maxTTL)
	return nil
}

func (s *Service) deleteEmailVerificationByToken(ctx context.Context, tokenHash string) {
	var data emailVerifyData
	if ok, _ := s.ephemGetJSON(ctx, keyEmailVerifyToken+tokenHash, &data); ok {
		for _, h := range uniqueTokenHashes(tokenHash, data.TokenHashes) {
			_ = s.ephemDel(ctx, keyEmailVerifyToken+h)
		}
		if data.UserID != "" {
			userKey := keyEmailVerifyUser + data.UserID
			if v, ok, _ := s.ephemGetString(ctx, userKey); ok && v != "" {
				for _, h := range uniqueTokenHashes(tokenHash, data.TokenHashes) {
					if v == h {
						_ = s.ephemDel(ctx, userKey)
						break
					}
				}
			}
		}
		return
	}
	_ = s.ephemDel(ctx, keyEmailVerifyToken+tokenHash)
}

func (s *Service) consumeEmailVerification(ctx context.Context, tokenHash string) (*emailVerifyToken, error) {
	var data emailVerifyData
	ok, err := s.ephemGetJSON(ctx, keyEmailVerifyToken+tokenHash, &data)
	if err != nil || !ok {
		return nil, jwt.ErrTokenUnverifiable
	}
	s.deleteEmailVerificationByToken(ctx, tokenHash)
	return &emailVerifyToken{UserID: data.UserID, Email: data.Email}, nil
}

// peekEmailVerification loads an email-verification record by token hash WITHOUT
// consuming it, so an email-scoped code check can reject a mismatch without
// destroying the legitimate owner's still-valid code (AK security audit F1).
func (s *Service) peekEmailVerification(ctx context.Context, tokenHash string) (*emailVerifyToken, bool) {
	var data emailVerifyData
	ok, err := s.ephemGetJSON(ctx, keyEmailVerifyToken+tokenHash, &data)
	if err != nil || !ok {
		return nil, false
	}
	return &emailVerifyToken{UserID: data.UserID, Email: data.Email}, true
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
	key := keyEmailVerifyCodeAttempts + email
	n := 0
	if v, ok, _ := s.ephemGetString(ctx, key); ok {
		n, _ = strconv.Atoi(v)
	}
	n++
	if n >= maxEmailVerifyCodeAttempts {
		s.invalidateEmailVerifyCodes(ctx, email)
		_ = s.ephemDel(ctx, key)
		return
	}
	_ = s.ephemSetString(ctx, key, strconv.Itoa(n), defaultEmailVerificationTTL)
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

// invalidateEmailVerifyCodes deletes every outstanding email-verification code and
// pending email registration for the address. Called when the per-email attempt
// cap is hit so brute-force guessing can't continue against a live code.
func (s *Service) invalidateEmailVerifyCodes(ctx context.Context, email string) {
	email = NormalizeEmail(strings.TrimSpace(email))
	if email == "" {
		return
	}
	// Pending email registration (new-signup flow).
	s.deletePendingChangeByTarget(ctx, KindRegisterEmail, email)
	// Existing-user email-verification tokens, via the per-user index.
	if s.pg != nil {
		if u, err := s.getUserByEmail(ctx, email); err == nil && u != nil {
			if tok, ok, _ := s.ephemGetString(ctx, keyEmailVerifyUser+u.ID); ok && tok != "" {
				s.deleteEmailVerificationByToken(ctx, tok)
			}
		}
	}
}

func (s *Service) storePasswordReset(ctx context.Context, tokenHash, userID string, ttl time.Duration) error {
	data := passwordResetData{UserID: userID}
	return s.ephemSetJSON(ctx, keyPasswordReset+tokenHash, data, ttl)
}

func (s *Service) consumePasswordReset(ctx context.Context, tokenHash string) (string, error) {
	var data passwordResetData
	ok, err := s.ephemGetJSON(ctx, keyPasswordReset+tokenHash, &data)
	if err != nil || !ok {
		return "", jwt.ErrTokenUnverifiable
	}
	_ = s.ephemDel(ctx, keyPasswordReset+tokenHash)
	return data.UserID, nil
}

func (s *Service) storePasswordResetSession(ctx context.Context, sessionHash, userID string, ttl time.Duration) error {
	data := passwordResetSessionData{UserID: userID}
	return s.ephemSetJSON(ctx, keyPasswordResetSession+sessionHash, data, ttl)
}

func (s *Service) consumePasswordResetSession(ctx context.Context, sessionHash string) (string, error) {
	var data passwordResetSessionData
	ok, err := s.ephemGetJSON(ctx, keyPasswordResetSession+sessionHash, &data)
	if err != nil || !ok {
		return "", jwt.ErrTokenUnverifiable
	}
	_ = s.ephemDel(ctx, keyPasswordResetSession+sessionHash)
	return data.UserID, nil
}

func (s *Service) storeMFACode(ctx context.Context, userID, codeHash, method, destination string, ttl time.Duration) error {
	data := twoFactorData{CodeHash: codeHash, Method: method, Destination: destination}
	return s.ephemSetJSON(ctx, keyTwoFactor+userID, data, ttl)
}

func (s *Service) consumeMFACode(ctx context.Context, userID, codeHash string) (bool, error) {
	var data twoFactorData
	ok, err := s.ephemGetJSON(ctx, keyTwoFactor+userID, &data)
	if err != nil || !ok {
		return false, nil
	}
	if data.CodeHash != codeHash {
		return false, nil
	}
	_ = s.ephemDel(ctx, keyTwoFactor+userID)
	return true, nil
}

func (s *Service) storeMFAReauthCode(ctx context.Context, userID, sessionID, codeHash, method, destination string, ttl time.Duration) error {
	data := twoFactorData{CodeHash: codeHash, Method: method, Destination: destination}
	return s.ephemSetJSON(ctx, keyTwoFactorReauth+userID+":"+sessionID, data, ttl)
}

func (s *Service) consumeMFAReauthCode(ctx context.Context, userID, sessionID, codeHash, method string) (bool, error) {
	var data twoFactorData
	key := keyTwoFactorReauth + userID + ":" + sessionID
	ok, err := s.ephemGetJSON(ctx, key, &data)
	if err != nil || !ok {
		return false, nil
	}
	if data.CodeHash != codeHash {
		return false, nil
	}
	if method != "" && !strings.EqualFold(strings.TrimSpace(data.Method), strings.TrimSpace(method)) {
		return false, nil
	}
	_ = s.ephemDel(ctx, key)
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
	ok, err := s.ephemGetJSON(ctx, keyPasskeyCeremony+challenge, &data)
	if err != nil || !ok {
		return data, jwt.ErrTokenUnverifiable
	}
	_ = s.ephemDel(ctx, keyPasskeyCeremony+challenge)
	return data, nil
}
