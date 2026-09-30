package authflow

import (
	"time"

	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/password"
	"github.com/open-rails/authkit/provider"
)

// Settings is the normalized engine configuration the HTTP layer reads,
// derived once from authkit.Config.
type Settings struct {
	Issuer               string
	AccountIssuers       []string
	ExpectedAudiences    []string
	RefreshTokenDuration time.Duration
	APIKeyPrefix         string
	Schema               string

	RequireMFAEnrollment    bool
	AllowPrivateNetworkJWKS bool
	DeviceKeys              bool
	PasswordlessLogin       bool
	SolanaNetwork           iam.SolanaNetwork
	Providers               []provider.Provider

	FrontendBaseURL string
	OIDCReturnPath  string

	RegistrationMode         iam.RegistrationMode
	RegistrationVerification iam.RegistrationVerificationPolicy
	Username                 iam.UsernamePolicy
	Password                 password.Policy

	Delegated DelegatedSettings
}

// DelegatedSettings are the delegated-token mint route's validated bounds.
type DelegatedSettings struct {
	Audiences                        []string
	AllowDPoP                        bool
	TTLFloor, TTLDefault, TTLCeiling time.Duration
}
