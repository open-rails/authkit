package core

import (
	"context"
	"fmt"
	"strings"
	"time"

	jwt "github.com/golang-jwt/jwt/v5"
)

const (
	keyPendingRegToken   = "auth:pending_reg:token:"
	keyPendingRegEmail   = "auth:pending_reg:email:"
	keyPendingRegUser    = "auth:pending_reg:user:"
	keyPendingPhoneToken = "auth:pending_phone:token:"
	keyPendingPhonePhone = "auth:pending_phone:phone:"
	keyPendingPhoneUser  = "auth:pending_phone:user:"
	keyPhoneVerify       = "auth:phone_verify:"
	keyEmailVerifyToken  = "auth:email_verify:token:"
	keyEmailVerifyUser   = "auth:email_verify:user:"
	keyPasswordReset     = "auth:password_reset:token:"
	keyTwoFactor         = "auth:2fa:code:"
)

type pendingRegistrationData struct {
	Email        string `json:"email"`
	Username     string `json:"username"`
	PasswordHash string `json:"password_hash"`
}

type phoneVerificationData struct {
	UserID   string `json:"user_id"`
	CodeHash string `json:"code_hash"`
	Purpose  string `json:"purpose"`
}

type emailVerifyData struct {
	UserID string  `json:"user_id"`
	Email  *string `json:"email,omitempty"`
}

type passwordResetData struct {
	UserID string `json:"user_id"`
}

type twoFactorData struct {
	CodeHash    string `json:"code_hash"`
	Method      string `json:"method"`
	Destination string `json:"destination"`
}

func (s *Service) storePendingRegistration(ctx context.Context, email, username, passwordHash, tokenHash string, ttl time.Duration) error {
	email = normalizeEmail(email)
	userKey := keyPendingRegUser + username
	emailKey := keyPendingRegEmail + email
	tokenKey := keyPendingRegToken + tokenHash

	if old, ok, _ := s.ephemGetString(ctx, emailKey); ok && old != "" && old != tokenHash {
		_ = s.ephemDel(ctx, keyPendingRegToken+old)
	}
	if old, ok, _ := s.ephemGetString(ctx, userKey); ok && old != "" && old != tokenHash {
		_ = s.ephemDel(ctx, keyPendingRegToken+old)
	}

	data := pendingRegistrationData{Email: email, Username: username, PasswordHash: passwordHash}
	if err := s.ephemSetJSON(ctx, tokenKey, data, ttl); err != nil {
		return err
	}
	_ = s.ephemSetString(ctx, emailKey, tokenHash, ttl)
	_ = s.ephemSetString(ctx, userKey, tokenHash, ttl)
	return nil
}

func (s *Service) loadPendingRegistration(ctx context.Context, tokenHash string) (pendingRegistrationData, bool, error) {
	var data pendingRegistrationData
	ok, err := s.ephemGetJSON(ctx, keyPendingRegToken+tokenHash, &data)
	return data, ok, err
}

func (s *Service) deletePendingRegistration(ctx context.Context, tokenHash string, data pendingRegistrationData) {
	_ = s.ephemDel(ctx, keyPendingRegToken+tokenHash)
	if data.Email != "" {
		_ = s.ephemDel(ctx, keyPendingRegEmail+normalizeEmail(data.Email))
	}
	if data.Username != "" {
		_ = s.ephemDel(ctx, keyPendingRegUser+data.Username)
	}
}

func (s *Service) storePendingPhoneRegistration(ctx context.Context, phone, username, passwordHash, tokenHash string, ttl time.Duration) error {
	phoneKey := keyPendingPhonePhone + phone
	userKey := keyPendingPhoneUser + username
	tokenKey := keyPendingPhoneToken + tokenHash

	if old, ok, _ := s.ephemGetString(ctx, phoneKey); ok && old != "" && old != tokenHash {
		_ = s.ephemDel(ctx, keyPendingPhoneToken+old)
	}
	if old, ok, _ := s.ephemGetString(ctx, userKey); ok && old != "" && old != tokenHash {
		_ = s.ephemDel(ctx, keyPendingPhoneToken+old)
	}

	data := pendingRegistrationData{Email: phone, Username: username, PasswordHash: passwordHash}
	if err := s.ephemSetJSON(ctx, tokenKey, data, ttl); err != nil {
		return err
	}
	_ = s.ephemSetString(ctx, phoneKey, tokenHash, ttl)
	_ = s.ephemSetString(ctx, userKey, tokenHash, ttl)
	return nil
}

func (s *Service) loadPendingPhoneRegistration(ctx context.Context, tokenHash string) (pendingRegistrationData, bool, error) {
	var data pendingRegistrationData
	ok, err := s.ephemGetJSON(ctx, keyPendingPhoneToken+tokenHash, &data)
	return data, ok, err
}

func (s *Service) deletePendingPhoneRegistration(ctx context.Context, tokenHash string, data pendingRegistrationData) {
	_ = s.ephemDel(ctx, keyPendingPhoneToken+tokenHash)
	if data.Email != "" {
		_ = s.ephemDel(ctx, keyPendingPhonePhone+data.Email)
	}
	if data.Username != "" {
		_ = s.ephemDel(ctx, keyPendingPhoneUser+data.Username)
	}
}

func (s *Service) phoneVerificationKey(purpose, phone string) string {
	purpose = strings.TrimSpace(purpose)
	if purpose == "" {
		purpose = "verify_phone"
	}
	return keyPhoneVerify + purpose + ":" + phone
}

func (s *Service) storePhoneVerification(ctx context.Context, purpose, phone, userID, codeHash string, ttl time.Duration) error {
	data := phoneVerificationData{UserID: userID, CodeHash: codeHash, Purpose: purpose}
	return s.ephemSetJSON(ctx, s.phoneVerificationKey(purpose, phone), data, ttl)
}

func (s *Service) consumePhoneVerification(ctx context.Context, purpose, phone, codeHash string) (string, error) {
	var data phoneVerificationData
	ok, err := s.ephemGetJSON(ctx, s.phoneVerificationKey(purpose, phone), &data)
	if err != nil || !ok {
		return "", jwt.ErrTokenUnverifiable
	}
	if data.CodeHash != codeHash {
		return "", jwt.ErrTokenUnverifiable
	}
	_ = s.ephemDel(ctx, s.phoneVerificationKey(purpose, phone))
	return data.UserID, nil
}

func (s *Service) storeEmailVerification(ctx context.Context, userID, tokenHash string, email *string, ttl time.Duration) error {
	userKey := keyEmailVerifyUser + userID
	if old, ok, _ := s.ephemGetString(ctx, userKey); ok && old != "" && old != tokenHash {
		_ = s.ephemDel(ctx, keyEmailVerifyToken+old)
	}
	data := emailVerifyData{UserID: userID, Email: email}
	if err := s.ephemSetJSON(ctx, keyEmailVerifyToken+tokenHash, data, ttl); err != nil {
		return err
	}
	_ = s.ephemSetString(ctx, userKey, tokenHash, ttl)
	return nil
}

func (s *Service) consumeEmailVerification(ctx context.Context, tokenHash string) (*emailVerifyToken, error) {
	var data emailVerifyData
	ok, err := s.ephemGetJSON(ctx, keyEmailVerifyToken+tokenHash, &data)
	if err != nil || !ok {
		return nil, jwt.ErrTokenUnverifiable
	}
	_ = s.ephemDel(ctx, keyEmailVerifyToken+tokenHash)
	if data.UserID != "" {
		userKey := keyEmailVerifyUser + data.UserID
		if v, ok, _ := s.ephemGetString(ctx, userKey); ok && v == tokenHash {
			_ = s.ephemDel(ctx, userKey)
		}
	}
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
