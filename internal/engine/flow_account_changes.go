package engine

import (
	"context"
	"fmt"
	"strings"

	"github.com/open-rails/authkit/auth"
	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/contact"
	"github.com/open-rails/authkit/internal/db"
	"github.com/open-rails/authkit/internal/errmodel"
	"github.com/open-rails/authkit/internal/httpapi"
	"github.com/open-rails/authkit/internal/ident"
)

// Account contact changes (email + phone): a request sends a code to the new
// address, and nothing changes until the code is confirmed
// (ConfirmVerification), signed in as the account. The challenge carries the
// change, so cancelling it is letting it expire.

// RequestPhoneChange sends a code to newPhone that moves userID's number there
// once confirmed, and answers its challenge. A number another account holds is
// answered alike and only its owner hears of the attempt.
func (s *Engine) RequestPhoneChange(ctx context.Context, userID, newPhone string) (string, error) {
	if s.pg == nil {
		return "", fmt.Errorf("postgres not configured")
	}
	if err := contact.ValidatePhone(newPhone); err != nil {
		return "", err
	}
	trimmed := contact.NormalizePhone(newPhone)

	u, err := s.getUserByID(ctx, userID)
	if err != nil {
		return "", err
	}
	if u == nil {
		return "", iam.ErrUserNotFound
	}
	same := u.PhoneNumber != nil && strings.EqualFold(*u.PhoneNumber, trimmed)
	if same && u.PhoneVerified {
		return "", errmodel.ErrPhoneAlreadyVerified
	}
	if !same {
		if err := refuseProofBesideUnproven(u, passwordlessChannelSMS); err != nil {
			return "", err
		}
	}
	if !s.admitCode(ctx, httpapi.RLVerifyRequestIdentifier, trimmed) {
		return newChallengeHandle(), nil
	}
	if same {
		return s.sendPhoneVerificationToUser(ctx, trimmed, userID)
	}
	if existing, _ := s.getUserByPhone(ctx, trimmed); existing != nil && existing.ID != userID {
		if s.sms == nil {
			return newChallengeHandle(), s.missingSender(errSMSNotConfigured)
		}
		return newChallengeHandle(), s.notifyAccountExists(ctx, "sms", trimmed)
	}
	return s.sendVerification(ctx, verificationChallenge{Kind: kindChangePhone, Target: trimmed, UserID: userID}, func(code, link string) error {
		if s.sms == nil {
			return s.missingSender(errSMSNotConfigured)
		}
		return s.sendSMS(ctx, iam.SMSMessage{Kind: iam.MessageVerification, To: trimmed, UserID: userID, Language: s.userLanguage(ctx, userID),
			Code: code, Link: s.phoneVerificationURL(link), Purpose: iam.PurposeContactChange})
	})
}

// RequestEmailChange is RequestPhoneChange for the email. The old address is
// not notified by AuthKit (only a security log line); a host that wants that
// notification sends it itself.
func (s *Engine) RequestEmailChange(ctx context.Context, userID, newEmail string) (string, error) {
	if s.pg == nil {
		return "", fmt.Errorf("postgres not configured")
	}
	if err := contact.ValidateEmail(newEmail); err != nil {
		return "", err
	}
	trimmed := contact.NormalizeEmail(newEmail)

	u, err := s.getUserByID(ctx, userID)
	if err != nil {
		return "", err
	}
	if u == nil {
		return "", iam.ErrUserNotFound
	}
	same := u.Email != nil && strings.EqualFold(*u.Email, trimmed)
	if same && u.EmailVerified {
		return "", errmodel.ErrEmailAlreadyVerified
	}
	if !same {
		if err := refuseProofBesideUnproven(u, passwordlessChannelEmail); err != nil {
			return "", err
		}
	}
	if !s.admitCode(ctx, httpapi.RLVerifyRequestIdentifier, trimmed) {
		return newChallengeHandle(), nil
	}
	if same {
		return s.sendEmailVerificationCode(ctx, u)
	}
	if existing, _ := s.getUserByEmail(ctx, trimmed); existing != nil && existing.ID != userID {
		if s.email == nil {
			return newChallengeHandle(), s.missingSender(errEmailNotConfigured)
		}
		return newChallengeHandle(), s.notifyAccountExists(ctx, "email", trimmed)
	}
	return s.sendVerification(ctx, verificationChallenge{Kind: kindChangeEmail, Target: trimmed, UserID: userID}, func(code, link string) error {
		if s.email == nil {
			return s.missingSender(errEmailNotConfigured)
		}
		return s.sendEmail(ctx, iam.EmailMessage{Kind: iam.MessageVerification, To: trimmed, Username: deref(u.Username), Language: s.userLanguage(ctx, userID),
			Code: code, Link: s.emailVerificationURL(link), Purpose: iam.PurposeContactChange})
	})
}

// RemovePhone clears the account's phone number under ACCT(root:users:manage),
// the account's own included. It is refused (ErrCannotRemoveLastContact)
// unless a proven email remains, so the account keeps an address to sign in
// and recover with, and an MFA holder keeps a proven contact. An account
// without a phone is unchanged.
func (s *Engine) RemovePhone(ctx context.Context, a auth.Identity, userID string) error {
	return s.withAccountMutation(ctx, a, userID, ident.RootUsersManage, selfAllowed, func(at accountTx) error {
		if _, err := contactStateForUpdate(ctx, at.tx, at.userID); err != nil {
			return err
		}
		u, err := at.q.UserByID(ctx, at.userID)
		if err != nil {
			return err
		}
		if u.PhoneNumber == nil {
			return nil
		}
		if u.Email == nil || !u.EmailVerified {
			return errmodel.ErrCannotRemoveLastContact
		}
		before, err := readAccountIdentity(ctx, at.tx, at.userID)
		if err != nil {
			return err
		}
		if err := at.q.UserSetPhone(ctx, db.UserSetPhoneParams{ID: at.userID}); err != nil {
			return err
		}
		changes, err := identityChanges(ctx, at.tx, at.userID, before)
		if err != nil {
			return err
		}
		return at.st.record(ctx, changes...)
	})
}
