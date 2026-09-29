package authflow

import (
	"time"
)

type TwoFactorSettings struct {
	UserID       string
	Enabled      bool
	Method       string // "email", "sms", or "totp"
	PhoneNumber  *string
	TOTPSecret   []byte
	LastTOTPStep *int64
	BackupCodes  []string // Hashed backup codes
	Factors      []TwoFactorFactor
	CreatedAt    time.Time
	UpdatedAt    time.Time
}

type TwoFactorFactor struct {
	ID           string
	UserID       string
	Method       string
	PhoneNumber  *string
	TOTPSecret   []byte
	LastTOTPStep *int64
	IsDefault    bool
	Enabled      bool
	CreatedAt    time.Time
	UpdatedAt    time.Time
}

// FactorEnrollmentMode distinguishes restricted enrollment grants from authenticated factor management.
type FactorEnrollmentMode string

const (
	// FirstFactorOnly permits a restricted grant to enroll only when no factor exists.
	FirstFactorOnly FactorEnrollmentMode = "first_factor_only"
	// AllowAdditionalFactors permits fresh authenticated users to add a new method.
	AllowAdditionalFactors FactorEnrollmentMode = "allow_additional_factors"
)
