package engine

// Second-factor enrollment as ONE engine decision (ak#318): which factor slot
// the caller may fill, the method/phone/code validation, the email/SMS setup code,
// the TOTP secret hand-out and the final enable.

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"
	"strings"

	jwt "github.com/golang-jwt/jwt/v5"

	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/authflow"
)

// BeginTwoFactorEnrollment decides the enrollment scope for a caller. An
// enrollment-only token (issued at login when a factor is mandatory) may fill
// the FIRST factor only, and only while no session or factor exists —
// ErrTwoFAFactorExists otherwise. A full session may add further factors.
func (s *Engine) BeginTwoFactorEnrollment(ctx context.Context, userID string, enrollmentToken bool, sessionID string) (authflow.TwoFactorEnrollmentScope, error) {
	factors, err := s.listUser2FAFactors(ctx, userID)
	if err != nil {
		return authflow.TwoFactorEnrollmentScope{}, stageErr("list_factors", err)
	}
	scope := authflow.TwoFactorEnrollmentScope{Mode: authflow.AllowAdditionalFactors, HasFactors: len(factors) > 0}
	if enrollmentToken {
		scope.Mode = authflow.FirstFactorOnly
		if sessionID != "" || scope.HasFactors {
			return scope, iam.ErrTwoFAFactorExists
		}
	}
	return scope, nil
}

// EnrollTwoFactor runs the enrollment decision tree. Input problems:
// ErrInvalidTwoFAMethod, ErrPhoneNumberRequired, ErrPhoneNumberMustBeE164,
// ErrInvalidCode, ErrTwoFACodeExpired, ErrTwoFAFactorExists; engine failures carry a stage
// prefix wrapping ErrPhoneTwoFAUnavailable / ErrTwoFASetupCodeSendFailed (with
// the delivery sentinel) / ErrTwoFAEnableFailed.
func (s *Engine) EnrollTwoFactor(ctx context.Context, in authflow.TwoFactorEnrollInput) (authflow.TwoFactorEnrollOutcome, error) {
	ctx, authErr := s.authorizeLoginEnrollment(ctx, in)
	if authErr != nil {
		return authflow.TwoFactorEnrollOutcome{}, authErr
	}
	// A deployment that mandates 2FA may still enroll the first factor; the
	// first contact proof retires it with every other pre-proof credential.
	if in.Mode != authflow.FirstFactorOnly {
		if err := s.RequireProvenContact(ctx, in.UserID); err != nil {
			return authflow.TwoFactorEnrollOutcome{}, err
		}
	}
	method := strings.ToLower(strings.TrimSpace(in.Method))
	factorID := strings.TrimSpace(in.FactorID)
	if method == "" && in.MakeDefault && factorID != "" {
		if err := s.setDefault2FAFactor(ctx, in.UserID, factorID); err != nil {
			return authflow.TwoFactorEnrollOutcome{}, stageErr("set_default_factor", fmt.Errorf("%w: %w", iam.ErrTwoFAEnableFailed, err))
		}
		return authflow.TwoFactorEnrollOutcome{Kind: authflow.TwoFactorEnrollDefaultSet}, nil
	}
	if method != "email" && method != "sms" && method != "totp" || !s.twoFactorMethodAvailable(method) {
		return authflow.TwoFactorEnrollOutcome{}, iam.ErrInvalidTwoFAMethod
	}
	code := strings.TrimSpace(in.Code)
	sessionID := ""
	if in.Mode == authflow.AllowAdditionalFactors {
		sessionID = strings.TrimSpace(in.SessionID)
	}
	var phone *string
	switch method {
	case "email":
		if code == "" {
			if err := s.sendEmail2FASetupCode(ctx, in.UserID); err != nil {
				if errors.Is(err, iam.ErrInvalidTwoFAMethod) {
					return authflow.TwoFactorEnrollOutcome{}, err
				}
				return authflow.TwoFactorEnrollOutcome{}, stageErr("send_email_2fa_setup", fmt.Errorf("%w: %w", iam.ErrTwoFASetupCodeSendFailed, err))
			}
			return authflow.TwoFactorEnrollOutcome{Kind: authflow.TwoFactorEnrollCodeSent, Method: method}, nil
		}
		valid, err := s.verifyEmail2FASetupCode(ctx, in.UserID, code)
		if err != nil {
			return authflow.TwoFactorEnrollOutcome{}, enrollmentProofError("verify_email_setup", err)
		}
		if !valid {
			return authflow.TwoFactorEnrollOutcome{}, iam.ErrInvalidCode
		}
	case "sms":
		p := strings.TrimSpace(in.PhoneNumber)
		if p == "" {
			return authflow.TwoFactorEnrollOutcome{}, iam.ErrPhoneNumberRequired
		}
		if !strings.HasPrefix(p, "+") {
			return authflow.TwoFactorEnrollOutcome{}, iam.ErrPhoneNumberMustBeE164
		}
		if code == "" {
			return s.startPhoneTwoFactorSetup(ctx, in.UserID, p)
		}
		valid, err := s.verifyPhone2FASetupCode(ctx, in.UserID, p, code)
		if err != nil {
			return authflow.TwoFactorEnrollOutcome{}, enrollmentProofError("verify_sms_setup", err)
		}
		if !valid {
			return authflow.TwoFactorEnrollOutcome{}, iam.ErrInvalidCode
		}
		phone = &p
	case "totp":
		if code == "" {
			secret, uri, err := s.startTOTPEnrollment(ctx, in.UserID)
			if err != nil {
				return authflow.TwoFactorEnrollOutcome{}, stageErr("start_totp", fmt.Errorf("%w: %w", iam.ErrTwoFAEnableFailed, err))
			}
			return authflow.TwoFactorEnrollOutcome{Kind: authflow.TwoFactorEnrollTOTPStarted, Method: method, Secret: secret, OTPAuthURI: uri}, nil
		}
		backupCodes, verified, err := s.enableTOTP2FA(ctx, totpEnrollment{UserID: in.UserID, Code: code, MakeDefault: in.MakeDefault, Mode: in.Mode}, sessionID)
		if err != nil {
			return authflow.TwoFactorEnrollOutcome{}, enrollmentProofError("enable_totp", err)
		}
		return s.completeFactorEnrollment(ctx, in, authflow.TwoFactorEnrollOutcome{Kind: authflow.TwoFactorEnrollEnabled, Method: method, BackupCodes: backupCodes, SessionVerified: verified})
	}
	backupCodes, verified, err := s.enable2FA(ctx, factorEnable{
		UserID: in.UserID, Method: method, Phone: phone, MakeDefault: in.MakeDefault, Mode: in.Mode, ProvenSessionID: sessionID,
	})
	if err != nil {
		if errors.Is(err, iam.ErrTwoFAFactorExists) {
			return authflow.TwoFactorEnrollOutcome{}, err
		}
		return authflow.TwoFactorEnrollOutcome{}, stageErr("enable_factor", fmt.Errorf("%w: %w", iam.ErrTwoFAEnableFailed, err))
	}
	return s.completeFactorEnrollment(ctx, in, authflow.TwoFactorEnrollOutcome{Kind: authflow.TwoFactorEnrollEnabled, Method: method, BackupCodes: backupCodes, SessionVerified: verified})
}

// startPhoneTwoFactorSetup sends the six-digit SMS setup code. Deliverability
// is gated up front so an undeliverable sender fails fast.
func (s *Engine) startPhoneTwoFactorSetup(ctx context.Context, userID, phone string) (authflow.TwoFactorEnrollOutcome, error) {
	if !s.SMSAvailable() {
		return authflow.TwoFactorEnrollOutcome{}, iam.ErrPhoneTwoFAUnavailable
	}
	n, err := rand.Int(rand.Reader, big.NewInt(900000))
	if err != nil {
		return authflow.TwoFactorEnrollOutcome{}, stageErr("generate_code", fmt.Errorf("%w: %w", iam.ErrTwoFASetupCodeSendFailed, err))
	}
	code := fmt.Sprintf("%06d", 100000+int(n.Int64()))
	if err := s.sendPhone2FASetupCode(ctx, userID, phone, code); err != nil {
		return authflow.TwoFactorEnrollOutcome{}, stageErr("send_phone_2fa_setup", fmt.Errorf("%w: %w", iam.ErrTwoFASetupCodeSendFailed, err))
	}
	return authflow.TwoFactorEnrollOutcome{Kind: authflow.TwoFactorEnrollCodeSent, Method: "sms"}, nil
}

// Only a rejected proof is an invalid code. Store and persistence failures must
// retain their cause so the transport reports and logs an operational failure.
func enrollmentProofError(stage string, err error) error {
	if errors.Is(err, jwt.ErrTokenUnverifiable) || errors.Is(err, jwt.ErrTokenInvalidClaims) {
		return iam.ErrInvalidCode
	}
	if known := iam.AsError(err); known != nil && known.Status < 500 {
		return err
	}
	return stageErr(stage, fmt.Errorf("%w: %w", iam.ErrTwoFAEnableFailed, err))
}
