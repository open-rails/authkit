package authflow

import (
	"time"

	"github.com/open-rails/authkit/authprovider"
	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/password"
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
	ApplicationRegistration bool
	DeviceKeys              bool
	PasswordlessLogin       bool
	SolanaNetwork           string
	Providers               []authprovider.Provider

	FrontendBaseURL string
	OIDCReturnPath  string

	RegistrationMode         iam.RegistrationMode
	RegistrationVerification iam.RegistrationVerificationPolicy
	Username                 iam.UsernamePolicy
	Password                 password.Policy

	Delegated DelegatedSettings
	Documents DocumentSettings
}

// DelegatedSettings are the delegated-token mint route's validated bounds.
type DelegatedSettings struct {
	Audiences                        []string
	AllowDPoP                        bool
	TTLFloor, TTLDefault, TTLCeiling time.Duration
}

// DocumentSettings authorize readers of the published-document surface.
type DocumentSettings struct {
	Readers             []DocumentReader
	AllowRegisteredTier bool
}

// DocumentReader pins one reader by exactly one identity.
type DocumentReader struct {
	ID, Domain, Issuer string
}
