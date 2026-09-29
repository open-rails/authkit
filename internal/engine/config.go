package engine

import (
	"fmt"
	"time"

	"github.com/open-rails/authkit/authprovider"
	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/rbac"
	"github.com/open-rails/authkit/jwtkit"
)

// The engine's settings mirror the public authkit configuration; the root
// package maps it field by field (config_map.go) and documents every field.

// Config is the engine's settings, normalized once at construction.
type Config struct {
	River                 RiverConfig
	Naming                iam.NamingConfig
	namingPolicy          iam.NamingPolicy
	Token                 TokenConfig
	Frontend              FrontendConfig
	Registration          RegistrationConfig
	Password              PasswordPolicy
	Username              iam.UsernamePolicy
	Keys                  KeysConfig
	Identity              IdentityConfig
	APIKeys               APIKeysConfig
	TwoFactor             TwoFactorConfig
	Passkeys              PasskeyConfig
	DeviceKeys            DeviceKeysConfig
	Roles                 RoleConfig
	Applications          ApplicationsConfig
	Delegated             DelegatedConfig
	Schema                string
	SolanaNetwork         iam.SolanaNetwork
	SessionEventRetention time.Duration
}

type PasswordPolicy struct {
	MinLength        int
	MaxLength        int
	RequireUppercase bool
	RequireLowercase bool
	RequireDigit     bool
	RequireSymbol    bool
	AllowCommon      bool
}

type ApplicationsConfig struct {
	AllowPrivateNetworkJWKS bool
}

type DelegatedConfig struct {
	AllowDPoP  bool
	Audiences  []string
	TTLFloor   time.Duration
	TTLDefault time.Duration
	TTLCeiling time.Duration
}

type TokenConfig struct {
	EntitlementAllowlist []string
	Issuer               string
	IssuedAudiences      []string
	ExpectedAudiences    []string
	AccessTokenDuration  time.Duration
	RefreshTokenDuration time.Duration
	SessionMaxPerUser    int
	RefreshRotationGrace time.Duration
	AccountIssuers       []string
}

type FrontendConfig struct {
	BaseURL           string
	OIDCReturnPath    string
	VerifyPath        string
	PasswordResetPath string
	PasswordlessPath  string
	InvitePath        string
}

type DeviceKeysConfig struct {
	Enabled bool
}

type RegistrationConfig struct {
	Verification                 iam.RegistrationVerificationPolicy
	NativeUserMode               iam.RegistrationMode
	PasswordlessLogin            bool
	PasswordlessAutoRegistration bool
	AllowMissingSenders          bool
	VerificationSendTimeout      time.Duration
}

type KeysConfig struct {
	Source                jwtkit.KeySource
	Path                  string
	AllowEphemeralDevKeys bool
	VerifyOnly            bool
}

type IdentityConfig struct {
	Providers []authprovider.Provider
}

type APIKeysConfig struct {
	Prefix string
	MaxTTL time.Duration
}

type TwoFactorConfig struct {
	Mode          iam.TwoFactorMode
	Methods       []iam.TwoFactorMethod
	TOTPSecretKey []byte
}

type PasskeyConfig struct {
	RPID             string
	RPDisplayName    string
	Origins          []string
	UserVerification string
}

type RoleConfig struct {
	Personas map[string]Persona
	Roles    []Role
}

type Persona struct {
	Permissions        []string
	RequireMFA         []string
	APIKeys            bool
	RemoteApplications bool
}

type Role struct {
	Persona     string
	Name        string
	Permissions []string
	Includes    []string
}

func (c RoleConfig) schema() (*rbac.Schema, error) {
	personas := make(map[string]rbac.PersonaSpec, len(c.Personas))
	for name, p := range c.Personas {
		personas[name] = rbac.PersonaSpec{
			Permissions:        p.Permissions,
			RequireMFA:         p.RequireMFA,
			APIKeys:            p.APIKeys,
			RemoteApplications: p.RemoteApplications,
		}
	}
	roles := make([]rbac.RoleSpec, 0, len(c.Roles))
	for _, r := range c.Roles {
		roles = append(roles, rbac.RoleSpec(r))
	}
	s, err := rbac.New(personas, roles)
	if err != nil {
		return nil, fmt.Errorf("authkit: Config.Roles: %w", err)
	}
	return s, nil
}
