package embedded

import (
	"context"
	"errors"
	"strings"
	"time"

	jwt "github.com/golang-jwt/jwt/v5"
	"github.com/jackc/pgx/v5"
)

// VerificationInput completes a delivered code/link. UserID and SessionID are
// supplied only from an authenticated host principal for contact changes.
type VerificationInput struct {
	Identifier string
	Code       string
	Token      string
	UserID     string
	SessionID  string
	UserAgent  string
	IP         string
}

// ConfirmVerification is the shared registration/contact-verification workflow.
// Verification that authenticates a user returns the same MFA/session outcome
// as password and provider login; a contact mutation returns contact_changed.
func (s *Client) ConfirmVerification(ctx context.Context, in VerificationInput) (LoginOutcome, error) {
	if in.Token != "" && in.Code != "" || in.Token == "" && (in.Identifier == "" || in.Code == "") {
		return LoginOutcome{}, jwt.ErrTokenInvalidClaims
	}
	kinds := []PendingChangeKind{KindRegisterEmail, KindRegisterPhone, KindVerifyEmail, KindVerifyPhone, KindChangeEmail, KindChangePhone}
	for _, kind := range kinds {
		if in.Identifier != "" && kind.isEmail() != strings.Contains(in.Identifier, "@") {
			continue
		}
		rec, ok, err := s.verificationRecord(ctx, kind, in)
		if err != nil {
			return LoginOutcome{}, err
		}
		if !ok {
			continue
		}
		if in.Token != "" {
			if !SecretEqual(rec.LinkHash, sha256Hex(in.Token)) {
				continue
			}
		} else if !SecretEqual(rec.CodeHash, sha256Hex(in.Code)) {
			continue
		}
		if err := s.claimPendingChange(ctx, rec); err != nil {
			return LoginOutcome{}, err
		}
		var account registeredAccount
		if kind.isRegister() {
			input := ImportUserInput{Username: rec.Username, PasswordHash: rec.PasswordHash, HashAlgo: "argon2id"}
			if kind.isEmail() {
				input.Email = rec.Target
				input.EmailVerified = true
			} else {
				input.PhoneNumber = rec.Target
				input.PhoneVerified = true
			}
			account, err = s.registerAccount(ctx, accountRegistration{User: input, Language: rec.PreferredLanguage, InviteToken: rec.AccountInviteToken})
		} else if kind == KindVerifyEmail || kind == KindVerifyPhone {
			channel := PasswordlessChannelEmail
			if !kind.isEmail() {
				channel = PasswordlessChannelSMS
			}
			account, err = s.verifyContactProof(ctx, rec.UserID, rec.Version, channel, rec.Target)
		} else {
			var keep *string
			if in.UserID == rec.UserID && in.SessionID != "" {
				keep = &in.SessionID
			}
			_, err = s.finalizePendingChange(ctx, rec, keep)
			if err != nil {
				return LoginOutcome{}, err
			}
			return LoginOutcome{Kind: LoginContactChanged, UserID: rec.UserID}, nil
		}
		if err != nil {
			return LoginOutcome{}, err
		}
		method, event := "email", "email_verification"
		if !kind.isEmail() {
			method, event = "sms", "phone_verification"
		}
		if kind.isEmail() {
			s.ClearEmailVerifyCodeAttempts(ctx, rec.Target)
		} else {
			s.ClearPhoneVerifyCodeAttempts(ctx, rec.Target)
		}
		return s.finishFirstFactor(ctx, loginProof{Version: account.Version, AuthenticatedAt: time.Now().UTC(), Contact: rec.Target, Input: LoginSessionInput{UserID: account.ID, AuthMethods: []string{method}, Event: event, UserAgent: in.UserAgent, IP: in.IP}})
	}
	if in.Token == "" {
		if strings.Contains(in.Identifier, "@") {
			s.RecordFailedEmailVerifyCode(ctx, in.Identifier)
		} else {
			s.RecordFailedPhoneVerifyCode(ctx, in.Identifier)
		}
	}
	return LoginOutcome{}, jwt.ErrTokenUnverifiable
}

func (s *Client) verificationRecord(ctx context.Context, kind PendingChangeKind, in VerificationInput) (pendingChange, bool, error) {
	if kind == KindVerifyEmail || kind == KindVerifyPhone {
		return s.existingVerificationRecord(ctx, kind, in)
	}
	var key string
	if in.Token != "" {
		var ok bool
		var err error
		key, ok, err = s.ephemGetString(ctx, pendingChangeLinkKey(kind, sha256Hex(in.Token)))
		if err != nil || !ok {
			return pendingChange{}, false, err
		}
	} else if kind.isRegister() {
		key = pendingChangeKey(kind, normalizePendingTarget(kind, in.Identifier))
	} else {
		if in.UserID == "" {
			return pendingChange{}, false, nil
		}
		key = pendingChangeKey(kind, in.UserID)
	}
	rec, ok, err := s.loadPendingChange(ctx, key)
	if err != nil || !ok {
		return rec, false, err
	}
	return rec, rec.Kind == kind && (in.Identifier == "" || rec.Target == normalizePendingTarget(kind, in.Identifier)), nil
}

func (s *Client) existingVerificationRecord(ctx context.Context, kind PendingChangeKind, in VerificationInput) (pendingChange, bool, error) {
	var key, linkKey string
	if in.Token != "" {
		prefix := keyEmailVerifyLink
		if kind == KindVerifyPhone {
			prefix = keyPhoneVerifyLink
		}
		linkKey = prefix + sha256Hex(in.Token)
		var ok bool
		var err error
		key, ok, err = s.ephemGetString(ctx, linkKey)
		if err != nil || !ok {
			return pendingChange{}, false, err
		}
	} else if kind == KindVerifyEmail {
		user, err := s.getUserByEmail(ctx, NormalizeEmail(in.Identifier))
		if errors.Is(err, pgx.ErrNoRows) || user == nil && err == nil {
			return pendingChange{}, false, nil
		}
		if err != nil {
			return pendingChange{}, false, err
		}
		key = keyEmailVerify + user.ID
	} else {
		key = phoneVerificationKey("verify_phone", in.Identifier)
	}
	rec := pendingChange{Kind: kind, storeKey: key, linkKey: linkKey}
	var raw []byte
	var ok bool
	var err error
	if kind == KindVerifyEmail {
		var data emailVerifyData
		raw, ok, err = s.ephemReadJSON(ctx, key, &data)
		rec.ID, rec.Version, rec.UserID, rec.CodeHash, rec.LinkHash = data.ID, data.Version, data.UserID, data.CodeHash, data.LinkHash
		if data.Email != nil {
			rec.Target = *data.Email
		}
		if rec.linkKey == "" && data.LinkHash != "" {
			rec.linkKey = keyEmailVerifyLink + data.LinkHash
		}
	} else {
		var data phoneVerificationData
		raw, ok, err = s.ephemReadJSON(ctx, key, &data)
		rec.ID, rec.Version, rec.UserID, rec.Target, rec.CodeHash, rec.LinkHash = data.ID, data.Version, data.UserID, data.Phone, data.CodeHash, data.LinkHash
		if data.Purpose != "verify_phone" {
			ok = false
		}
		if rec.linkKey == "" && data.LinkHash != "" {
			rec.linkKey = keyPhoneVerifyLink + data.LinkHash
		}
	}
	if err != nil {
		return rec, false, err
	}
	rec.expected = raw
	return rec, ok && rec.ID != "" && rec.Version > 0 && rec.UserID != "" && rec.Target != "" && (in.Identifier == "" || rec.Target == normalizePendingTarget(kind, in.Identifier)), nil
}
