package engine

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"
	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/contact"
	"github.com/open-rails/authkit/internal/db"
	"github.com/open-rails/authkit/internal/httpapi"
)

// getUserByPhone returns a user by phone number (if any)
func (s *Engine) getUserByPhone(ctx context.Context, phone string) (*db.User, error) {
	if s.pg == nil {
		return nil, nil
	}
	r, err := s.q.UserByPhone(ctx, db.UserByPhoneParams{TenantID: s.tenantKey(ctx), Phone: &phone})
	if err != nil {
		return nil, err
	}
	return &r, nil
}

// RequestEmailVerification sends a verification code to an account or pending
// registration whose address is unproven, and answers its challenge. An
// unknown or already verified address, or one past its send quota, gets a
// challenge too, naming nothing, so the answer reveals none of them.
func (s *Engine) RequestEmailVerification(ctx context.Context, email string) (string, error) {
	email = contact.NormalizeEmail(email)
	if err := contact.ValidateEmail(email); err != nil {
		return "", err
	}
	if !s.admitCode(ctx, httpapi.RLVerifyRequestIdentifier, email) {
		return newChallengeHandle(), nil
	}
	return s.requestEmailVerification(ctx, email)
}

// requestEmailVerification is RequestEmailVerification outside any quota.
func (s *Engine) requestEmailVerification(ctx context.Context, email string) (string, error) {
	if s.pg != nil {
		u, err := s.getUserByEmail(ctx, email)
		if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return "", err
		}
		if u != nil {
			if err := s.renewTakenRegistration(ctx, kindRegisterEmail, email); err != nil {
				return "", err
			}
			if u.EmailVerified {
				return newChallengeHandle(), nil
			}
			return s.sendEmailVerificationCode(ctx, u)
		}
	}
	handle, found, err := s.resendRegistration(ctx, email)
	if found || err != nil {
		return handle, err
	}
	return newChallengeHandle(), s.requirePG()
}

// sendEmailVerificationCode sends a code proving the mailbox, proven before or
// not: a deleted account's restore asks for it again.
func (s *Engine) sendEmailVerificationCode(ctx context.Context, u *db.User) (string, error) {
	if u == nil || u.Email == nil {
		return "", iam.ErrUserNotFound
	}
	return s.sendVerification(ctx, verificationChallenge{Kind: kindVerifyEmail, Target: *u.Email, UserID: u.ID}, func(code, link string) error {
		if s.email == nil {
			return errEmailNotConfigured
		}
		return s.sendEmail(ctx, iam.EmailMessage{Kind: iam.MessageVerification, To: *u.Email, Username: deref(u.Username), Language: s.userLanguage(ctx, u.ID),
			Code: code, Link: s.emailVerificationURL(link), Purpose: iam.PurposeContactVerify})
	})
}

// --- Phone Verification (for existing users with unverified phones) ---

// RequestPhoneVerification is RequestEmailVerification for a phone number.
func (s *Engine) RequestPhoneVerification(ctx context.Context, phone string) (string, error) {
	phone = contact.NormalizePhone(phone)
	if err := contact.ValidatePhone(phone); err != nil {
		return "", err
	}
	if !s.admitCode(ctx, httpapi.RLVerifyRequestIdentifier, phone) {
		return newChallengeHandle(), nil
	}
	if s.pg != nil {
		u, err := s.getUserByPhone(ctx, phone)
		if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return "", err
		}
		if u != nil {
			if err := s.renewTakenRegistration(ctx, kindRegisterPhone, phone); err != nil {
				return "", err
			}
			if u.PhoneVerified || u.PhoneNumber == nil {
				return newChallengeHandle(), nil
			}
			return s.sendPhoneVerificationToUser(ctx, *u.PhoneNumber, u.ID)
		}
	}
	handle, found, err := s.resendRegistration(ctx, phone)
	if found || err != nil {
		return handle, err
	}
	return newChallengeHandle(), s.requirePG()
}

// sendPhoneVerificationToUser sends a code proving phone, userID's number,
// and answers its challenge.
func (s *Engine) sendPhoneVerificationToUser(ctx context.Context, phone, userID string) (string, error) {
	return s.sendVerification(ctx, verificationChallenge{Kind: kindVerifyPhone, Target: phone, UserID: userID}, func(code, link string) error {
		if s.sms == nil {
			return errSMSNotConfigured
		}
		return s.sendSMS(ctx, iam.SMSMessage{Kind: iam.MessageVerification, To: phone, UserID: userID, Language: s.userLanguage(ctx, userID),
			Code: code, Link: s.phoneVerificationURL(link), Purpose: iam.PurposeContactVerify})
	})
}
