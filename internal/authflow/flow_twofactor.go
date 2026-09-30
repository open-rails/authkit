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
	Factors      []MFAFactor
	CreatedAt    time.Time
	UpdatedAt    time.Time
}

// MFAFactor is a stored second factor; TwoFactorFactor is how the wire shows
// it.
type MFAFactor struct {
	ID          string
	UserID      string
	Method      string
	PhoneNumber *string
	// Email is the address an email factor was proven for; its codes go
	// there, never to the account's current address.
	Email        *string
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
