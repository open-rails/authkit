package core

import (
	"context"
	"fmt"
	"strings"
	"time"

	jwt "github.com/golang-jwt/jwt/v5"
)

const (
	keyPendingRegToken      = "auth:pending_reg:token:"
	keyPendingRegEmail      = "auth:pending_reg:email:"
	keyPendingRegUser       = "auth:pending_reg:user:"
	keyPendingPhoneToken    = "auth:pending_phone:token:"
	keyPendingPhonePhone    = "auth:pending_phone:phone:"
	keyPendingPhoneUser     = "auth:pending_phone:user:"
	keyPhoneVerifyToken     = "auth:phone_verify:token:"
	keyPhoneVerifyIndex     = "auth:phone_verify:index:"
	keyEmailVerifyToken     = "auth:email_verify:token:"
	keyEmailVerifyUser      = "auth:email_verify:user:"
	keyPasswordReset        = "auth:password_reset:token:"
	keyPasswordResetSession = "auth:password_reset:session:"
	keyTwoFactor            = "auth:2fa:code:"
	keyTwoFactorChallenge   = "auth:2fa:challenge:"
)

type pendingRegistrationData struct {
	Email        string   `json:"email"`
	Username     string   `json:"username"`
	PasswordHash string   `json:"password_hash"`
	TokenHashes  []string `json:"token_hashes,omitempty"`
}

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

func (s *Service) storePendingRegistration(ctx context.Context, email, username, passwordHash, tokenHash string, ttl time.Duration) error {
	return s.storePendingRegistrationTokens(ctx, email, username, passwordHash, map[string]time.Duration{tokenHash: ttl})
}

func (s *Service) storePendingRegistrationTokens(ctx context.Context, email, username, passwordHash string, tokenTTLs map[string]time.Duration) error {
	email = normalizeEmail(email)
	userKey := keyPendingRegUser + username
	emailKey := keyPendingRegEmail + email

	normalizedTTLs, canonicalHash, maxTTL, err := normalizeTokenTTLs(tokenTTLs, 15*time.Minute)
	if err != nil {
		return err
	}

	if old, ok, _ := s.ephemGetString(ctx, emailKey); ok && old != "" {
		s.deletePendingRegistrationByToken(ctx, old)
	}
	if old, ok, _ := s.ephemGetString(ctx, userKey); ok && old != "" {
		s.deletePendingRegistrationByToken(ctx, old)
	}

	data := pendingRegistrationData{
		Email:        email,
		Username:     username,
		PasswordHash: passwordHash,
		TokenHashes:  uniqueTokenHashes(canonicalHash, nil),
	}
	for tokenHash := range normalizedTTLs {
		data.TokenHashes = uniqueTokenHashes(tokenHash, data.TokenHashes)
	}

	for tokenHash, ttl := range normalizedTTLs {
		if err := s.ephemSetJSON(ctx, keyPendingRegToken+tokenHash, data, ttl); err != nil {
			return err
		}
	}

	_ = s.ephemSetString(ctx, emailKey, canonicalHash, maxTTL)
	_ = s.ephemSetString(ctx, userKey, canonicalHash, maxTTL)
	return nil
}

func (s *Service) loadPendingRegistration(ctx context.Context, tokenHash string) (pendingRegistrationData, bool, error) {
	var data pendingRegistrationData
	ok, err := s.ephemGetJSON(ctx, keyPendingRegToken+tokenHash, &data)
	return data, ok, err
}

func (s *Service) deletePendingRegistrationByToken(ctx context.Context, tokenHash string) {
	var data pendingRegistrationData
	if ok, _ := s.ephemGetJSON(ctx, keyPendingRegToken+tokenHash, &data); ok {
		s.deletePendingRegistration(ctx, tokenHash, data)
		return
	}
	_ = s.ephemDel(ctx, keyPendingRegToken+tokenHash)
}

func (s *Service) deletePendingRegistration(ctx context.Context, tokenHash string, data pendingRegistrationData) {
	for _, h := range uniqueTokenHashes(tokenHash, data.TokenHashes) {
		_ = s.ephemDel(ctx, keyPendingRegToken+h)
	}
	if data.Email != "" {
		_ = s.ephemDel(ctx, keyPendingRegEmail+normalizeEmail(data.Email))
	}
	if data.Username != "" {
		_ = s.ephemDel(ctx, keyPendingRegUser+data.Username)
	}
}

func (s *Service) storePendingPhoneRegistration(ctx context.Context, phone, username, passwordHash, tokenHash string, ttl time.Duration) error {
	return s.storePendingPhoneRegistrationTokens(ctx, phone, username, passwordHash, map[string]time.Duration{tokenHash: ttl})
}

func (s *Service) storePendingPhoneRegistrationTokens(ctx context.Context, phone, username, passwordHash string, tokenTTLs map[string]time.Duration) error {
	phoneKey := keyPendingPhonePhone + phone
	userKey := keyPendingPhoneUser + username

	normalizedTTLs, canonicalHash, maxTTL, err := normalizeTokenTTLs(tokenTTLs, 15*time.Minute)
	if err != nil {
		return err
	}

	if old, ok, _ := s.ephemGetString(ctx, phoneKey); ok && old != "" {
		s.deletePendingPhoneRegistrationByToken(ctx, old)
	}
	if old, ok, _ := s.ephemGetString(ctx, userKey); ok && old != "" {
		s.deletePendingPhoneRegistrationByToken(ctx, old)
	}

	data := pendingRegistrationData{
		Email:        phone,
		Username:     username,
		PasswordHash: passwordHash,
		TokenHashes:  uniqueTokenHashes(canonicalHash, nil),
	}
	for tokenHash := range normalizedTTLs {
		data.TokenHashes = uniqueTokenHashes(tokenHash, data.TokenHashes)
	}

	for tokenHash, ttl := range normalizedTTLs {
		if err := s.ephemSetJSON(ctx, keyPendingPhoneToken+tokenHash, data, ttl); err != nil {
			return err
		}
	}

	_ = s.ephemSetString(ctx, phoneKey, canonicalHash, maxTTL)
	_ = s.ephemSetString(ctx, userKey, canonicalHash, maxTTL)
	return nil
}

func (s *Service) loadPendingPhoneRegistration(ctx context.Context, tokenHash string) (pendingRegistrationData, bool, error) {
	var data pendingRegistrationData
	ok, err := s.ephemGetJSON(ctx, keyPendingPhoneToken+tokenHash, &data)
	return data, ok, err
}

func (s *Service) deletePendingPhoneRegistrationByToken(ctx context.Context, tokenHash string) {
	var data pendingRegistrationData
	if ok, _ := s.ephemGetJSON(ctx, keyPendingPhoneToken+tokenHash, &data); ok {
		s.deletePendingPhoneRegistration(ctx, tokenHash, data)
		return
	}
	_ = s.ephemDel(ctx, keyPendingPhoneToken+tokenHash)
}

func (s *Service) deletePendingPhoneRegistration(ctx context.Context, tokenHash string, data pendingRegistrationData) {
	for _, h := range uniqueTokenHashes(tokenHash, data.TokenHashes) {
		_ = s.ephemDel(ctx, keyPendingPhoneToken+h)
	}
	if data.Email != "" {
		_ = s.ephemDel(ctx, keyPendingPhonePhone+data.Email)
	}
	if data.Username != "" {
		_ = s.ephemDel(ctx, keyPendingPhoneUser+data.Username)
	}
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

	normalizedTTLs, canonicalHash, maxTTL, err := normalizeTokenTTLs(tokenTTLs, 15*time.Minute)
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

func (s *Service) getPhoneVerification(ctx context.Context, purpose, phone string) (*phoneVerificationData, error) {
	purpose = normalizePhoneVerificationPurpose(purpose)
	tokenHash, ok, err := s.ephemGetString(ctx, s.phoneVerificationIndexKey(purpose, phone))
	if err != nil || !ok || tokenHash == "" {
		return nil, fmt.Errorf("not found")
	}
	var data phoneVerificationData
	ok, err = s.ephemGetJSON(ctx, s.phoneVerificationTokenKey(purpose, tokenHash), &data)
	if err != nil || !ok {
		return nil, fmt.Errorf("not found")
	}
	return &data, nil
}

func (s *Service) storeEmailVerification(ctx context.Context, userID, tokenHash string, email *string, ttl time.Duration) error {
	return s.storeEmailVerificationTokens(ctx, userID, email, map[string]time.Duration{tokenHash: ttl})
}

func (s *Service) storeEmailVerificationTokens(ctx context.Context, userID string, email *string, tokenTTLs map[string]time.Duration) error {
	userKey := keyEmailVerifyUser + userID

	normalizedTTLs, canonicalHash, maxTTL, err := normalizeTokenTTLs(tokenTTLs, 15*time.Minute)
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

func (s *Service) getEmailVerificationByUser(ctx context.Context, userID string) (*emailVerifyToken, error) {
	userKey := keyEmailVerifyUser + userID
	tokenHash, ok, err := s.ephemGetString(ctx, userKey)
	if err != nil || !ok || tokenHash == "" {
		return nil, fmt.Errorf("no pending email change found")
	}
	var data emailVerifyData
	ok, err = s.ephemGetJSON(ctx, keyEmailVerifyToken+tokenHash, &data)
	if err != nil || !ok {
		return nil, fmt.Errorf("no pending email change found")
	}
	return &emailVerifyToken{UserID: data.UserID, Email: data.Email}, nil
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

func (s *Service) storeTwoFactorCode(ctx context.Context, userID, codeHash, method, destination string, ttl time.Duration) error {
	data := twoFactorData{CodeHash: codeHash, Method: method, Destination: destination}
	return s.ephemSetJSON(ctx, keyTwoFactor+userID, data, ttl)
}

func (s *Service) consumeTwoFactorCode(ctx context.Context, userID, codeHash string) (bool, error) {
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

func (s *Service) storeTwoFactorChallenge(ctx context.Context, userID, challengeHash string, ttl time.Duration) error {
	return s.ephemSetString(ctx, keyTwoFactorChallenge+userID, challengeHash, ttl)
}

func (s *Service) getTwoFactorChallenge(ctx context.Context, userID string) (string, bool, error) {
	return s.ephemGetString(ctx, keyTwoFactorChallenge+userID)
}

func (s *Service) deleteTwoFactorChallenge(ctx context.Context, userID string) error {
	return s.ephemDel(ctx, keyTwoFactorChallenge+userID)
}
