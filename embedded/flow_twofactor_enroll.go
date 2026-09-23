package embedded

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

	authkit "github.com/open-rails/authkit"
)

var (
	ErrInvalidTwoFAMethod       = authkit.ErrInvalidTwoFAMethod
	ErrPhoneNumberRequired      = authkit.ErrPhoneNumberRequired
	ErrPhoneNumberMustBeE164    = authkit.ErrPhoneNumberMustBeE164
	ErrInvalidCode              = authkit.ErrInvalidCode
	ErrPhoneTwoFAUnavailable    = authkit.ErrPhoneTwoFAUnavailable
	ErrTwoFASetupCodeSendFailed = authkit.ErrTwoFASetupCodeSendFailed
	ErrTwoFAEnableFailed        = authkit.ErrTwoFAEnableFailed
	ErrTwoFAFactorExists        = authkit.ErrTwoFAFactorExists
)

// TwoFactorEnrollmentScope is what an enrollment call may do: the factor
// slot policy and whether the account already holds a factor.
type TwoFactorEnrollmentScope struct {
	Mode       FactorEnrollmentMode
	HasFactors bool
}

// BeginTwoFactorEnrollment decides the enrollment scope for a caller. An
// enrollment-only token (issued at login when a factor is mandatory) may fill
// the FIRST factor only, and only while no session or factor exists —
// ErrTwoFAFactorExists otherwise. A full session may add further factors.
func (s *engine) BeginTwoFactorEnrollment(ctx context.Context, userID string, enrollmentToken bool, sessionID string) (TwoFactorEnrollmentScope, error) {
	factors, err := s.List2FAFactors(ctx, userID)
	if err != nil {
		return TwoFactorEnrollmentScope{}, stageErr("list_factors", err)
	}
	scope := TwoFactorEnrollmentScope{Mode: AllowAdditionalFactors, HasFactors: len(factors) > 0}
	if enrollmentToken {
		scope.Mode = FirstFactorOnly
		if sessionID != "" || scope.HasFactors {
			return scope, ErrTwoFAFactorExists
		}
	}
	return scope, nil
}

// TwoFactorEnrollInput is one enrollment request.
type TwoFactorEnrollInput struct {
	LoginChallenge string
	// SessionID is the caller's session; a confirmed code marks it 2FA-verified.
	SessionID   string
	UserAgent   string
	IP          string
	UserID      string
	Mode        FactorEnrollmentMode
	Method      string // "email" | "sms" | "totp"; empty with FactorID+MakeDefault re-points the default
	Code        string // email/SMS setup code or TOTP code; empty starts the method's setup
	PhoneNumber string
	MakeDefault bool
	FactorID    string
}

// TwoFactorEnrollKind is the closed set of enrollment results.
type TwoFactorEnrollKind string

const (
	TwoFactorEnrollDefaultSet  TwoFactorEnrollKind = "default_set"
	TwoFactorEnrollCodeSent    TwoFactorEnrollKind = "code_sent"    // email/SMS setup code delivered
	TwoFactorEnrollTOTPStarted TwoFactorEnrollKind = "totp_started" // secret + otpauth URI handed out
	TwoFactorEnrollEnabled     TwoFactorEnrollKind = "enabled"
)

// TwoFactorEnrollOutcome carries the TOTP material for TwoFactorEnrollTOTPStarted
// and the plaintext backup codes (shown once) for TwoFactorEnrollEnabled.
// SessionVerified reports that the input session now holds 2FA assurance.
type TwoFactorEnrollOutcome struct {
	Login           *LoginOutcome
	Kind            TwoFactorEnrollKind
	Method          string
	Secret          string
	OTPAuthURI      string
	BackupCodes     []string
	SessionVerified bool
}

// EnrollTwoFactor runs the enrollment decision tree. Input problems:
// ErrInvalidTwoFAMethod, ErrPhoneNumberRequired, ErrPhoneNumberMustBeE164,
// ErrInvalidCode, ErrTwoFAFactorExists; engine failures carry a stage
// prefix wrapping ErrPhoneTwoFAUnavailable / ErrTwoFASetupCodeSendFailed (with
// the delivery sentinel) / ErrTwoFAEnableFailed.
func (s *engine) EnrollTwoFactor(ctx context.Context, in TwoFactorEnrollInput) (TwoFactorEnrollOutcome, error) {
	ctx, authErr := s.authorizeLoginEnrollment(ctx, in)
	if authErr != nil {
		return TwoFactorEnrollOutcome{}, authErr
	}
	method := strings.ToLower(strings.TrimSpace(in.Method))
	factorID := strings.TrimSpace(in.FactorID)
	if method == "" && in.MakeDefault && factorID != "" {
		if err := s.SetDefault2FAFactor(ctx, in.UserID, factorID); err != nil {
			return TwoFactorEnrollOutcome{}, stageErr("set_default_factor", fmt.Errorf("%w: %w", ErrTwoFAEnableFailed, err))
		}
		return TwoFactorEnrollOutcome{Kind: TwoFactorEnrollDefaultSet}, nil
	}
	if method != "email" && method != "sms" && method != "totp" || !s.TwoFactorMethodAvailable(method) {
		return TwoFactorEnrollOutcome{}, ErrInvalidTwoFAMethod
	}
	code := strings.TrimSpace(in.Code)
	sessionID := ""
	if in.Mode == AllowAdditionalFactors {
		sessionID = strings.TrimSpace(in.SessionID)
	}
	var phone *string
	switch method {
	case "email":
		if code == "" {
			if err := s.sendEmail2FASetupCode(ctx, in.UserID); err != nil {
				if errors.Is(err, ErrInvalidTwoFAMethod) {
					return TwoFactorEnrollOutcome{}, err
				}
				return TwoFactorEnrollOutcome{}, stageErr("send_email_2fa_setup", fmt.Errorf("%w: %w", ErrTwoFASetupCodeSendFailed, err))
			}
			return TwoFactorEnrollOutcome{Kind: TwoFactorEnrollCodeSent, Method: method}, nil
		}
		valid, err := s.verifyEmail2FASetupCode(ctx, in.UserID, code)
		if err != nil {
			return TwoFactorEnrollOutcome{}, enrollmentProofError("verify_email_setup", err)
		}
		if !valid {
			return TwoFactorEnrollOutcome{}, ErrInvalidCode
		}
	case "sms":
		p := strings.TrimSpace(in.PhoneNumber)
		if p == "" {
			return TwoFactorEnrollOutcome{}, ErrPhoneNumberRequired
		}
		if !strings.HasPrefix(p, "+") {
			return TwoFactorEnrollOutcome{}, ErrPhoneNumberMustBeE164
		}
		if code == "" {
			return s.startPhoneTwoFactorSetup(ctx, in.UserID, p)
		}
		valid, err := s.VerifyPhone2FASetupCode(ctx, in.UserID, p, code)
		if err != nil {
			return TwoFactorEnrollOutcome{}, enrollmentProofError("verify_sms_setup", err)
		}
		if !valid {
			return TwoFactorEnrollOutcome{}, ErrInvalidCode
		}
		phone = &p
	case "totp":
		if code == "" {
			secret, uri, err := s.StartTOTPEnrollment(ctx, in.UserID)
			if err != nil {
				return TwoFactorEnrollOutcome{}, stageErr("start_totp", fmt.Errorf("%w: %w", ErrTwoFAEnableFailed, err))
			}
			return TwoFactorEnrollOutcome{Kind: TwoFactorEnrollTOTPStarted, Method: method, Secret: secret, OTPAuthURI: uri}, nil
		}
		backupCodes, verified, err := s.enableTOTP2FA(ctx, TOTPEnrollment{UserID: in.UserID, Code: code, MakeDefault: in.MakeDefault, Mode: in.Mode}, sessionID)
		if err != nil {
			return TwoFactorEnrollOutcome{}, enrollmentProofError("enable_totp", err)
		}
		return s.completeFactorEnrollment(ctx, in, TwoFactorEnrollOutcome{Kind: TwoFactorEnrollEnabled, Method: method, BackupCodes: backupCodes, SessionVerified: verified})
	}
	backupCodes, verified, err := s.enable2FA(ctx, factorEnable{
		UserID: in.UserID, Method: method, Phone: phone, MakeDefault: in.MakeDefault, Mode: in.Mode, ProvenSessionID: sessionID,
	})
	if err != nil {
		if errors.Is(err, ErrTwoFAFactorExists) {
			return TwoFactorEnrollOutcome{}, err
		}
		return TwoFactorEnrollOutcome{}, stageErr("enable_factor", fmt.Errorf("%w: %w", ErrTwoFAEnableFailed, err))
	}
	return s.completeFactorEnrollment(ctx, in, TwoFactorEnrollOutcome{Kind: TwoFactorEnrollEnabled, Method: method, BackupCodes: backupCodes, SessionVerified: verified})
}

// startPhoneTwoFactorSetup sends the six-digit SMS setup code. Deliverability
// is gated up front so an undeliverable sender fails fast.
func (s *engine) startPhoneTwoFactorSetup(ctx context.Context, userID, phone string) (TwoFactorEnrollOutcome, error) {
	if !s.SMSAvailable() {
		return TwoFactorEnrollOutcome{}, ErrPhoneTwoFAUnavailable
	}
	n, err := rand.Int(rand.Reader, big.NewInt(900000))
	if err != nil {
		return TwoFactorEnrollOutcome{}, stageErr("generate_code", fmt.Errorf("%w: %w", ErrTwoFASetupCodeSendFailed, err))
	}
	code := fmt.Sprintf("%06d", 100000+int(n.Int64()))
	if err := s.SendPhone2FASetupCode(ctx, userID, phone, code); err != nil {
		return TwoFactorEnrollOutcome{}, stageErr("send_phone_2fa_setup", fmt.Errorf("%w: %w", ErrTwoFASetupCodeSendFailed, err))
	}
	return TwoFactorEnrollOutcome{Kind: TwoFactorEnrollCodeSent, Method: "sms"}, nil
}

// Only a rejected proof is an invalid code. Store and persistence failures must
// retain their cause so the transport reports and logs an operational failure.
func enrollmentProofError(stage string, err error) error {
	if errors.Is(err, jwt.ErrTokenUnverifiable) || errors.Is(err, jwt.ErrTokenInvalidClaims) {
		return ErrInvalidCode
	}
	if known := authkit.AsError(err); known != nil && known.Status < 500 {
		return err
	}
	return stageErr(stage, fmt.Errorf("%w: %w", ErrTwoFAEnableFailed, err))
}
