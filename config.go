package authkit

import (
	"github.com/open-rails/authkit/internal/config"
	"github.com/open-rails/authkit/internal/httpapi"
)

// The configuration is defined once, in internal/config; these names are how
// hosts spell it. go doc prints only the alias: the field docs are on
// pkg.go.dev/github.com/open-rails/authkit/internal/config and in gopls.

type (
	// Config is the host configuration: plain data. Everything that reaches
	// outside the process is in Deps.
	Config             = config.Config
	TokenConfig        = config.TokenConfig
	KeysConfig         = config.KeysConfig
	FrontendConfig     = config.FrontendConfig
	RegistrationConfig = config.RegistrationConfig
	PasswordPolicy     = config.PasswordPolicy
	UsernameConfig     = config.UsernameConfig
	FormerNamesConfig  = config.FormerNamesConfig
	FormerNamesMode    = config.FormerNamesMode
	TwoFactorConfig    = config.TwoFactorConfig
	PasskeyConfig      = config.PasskeyConfig
	DeviceKeysConfig   = config.DeviceKeysConfig
	APIKeysConfig      = config.APIKeysConfig
	DelegatedConfig    = config.DelegatedConfig
	InvitationsConfig  = config.InvitationsConfig
	// RemoteApplicationConfig declares one remote application
	// (Config.RemoteApplications).
	RemoteApplicationConfig = config.RemoteApplicationConfig
	LanguageConfig          = config.LanguageConfig
	RiverConfig             = config.RiverConfig
	HTTPConfig              = config.HTTPConfig
	RateLimit               = config.RateLimit
)

// Former-name reservation modes.
const (
	FormerNamesFinite    = config.FormerNamesFinite
	FormerNamesForever   = config.FormerNamesForever
	FormerNamesImmediate = config.FormerNamesImmediate
)

// DefaultRateLimits returns AuthKit's built-in per-endpoint limits, keyed by
// bucket name ("default" applies to unlisted buckets).
func DefaultRateLimits() map[string]RateLimit { return httpapi.DefaultRateLimits() }
