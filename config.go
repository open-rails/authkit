package authkit

import (
	"github.com/open-rails/authkit/internal/config"
)

// The configuration is defined once, in internal/config; these names are how
// hosts spell it. go doc prints only the alias: the field docs are on
// pkg.go.dev/github.com/open-rails/authkit/internal/config and in gopls.

type (
	// Config is the host configuration: plain data. Everything that reaches
	// outside the process is in Deps.
	Config               = config.Config
	DatabaseConfig       = config.DatabaseConfig
	NotificationProducer = config.NotificationProducer
	Tenancy              = config.Tenancy
	AgreementConfig      = config.AgreementConfig
	// AuthorizationServerConfig declares the OAuth clients and resource
	// servers of the authorization server (Config.AuthorizationServer).
	AuthorizationServerConfig = config.AuthorizationServerConfig
	OAuthClientConfig         = config.OAuthClientConfig
	// GroupClientsConfig is what groups' OAuth clients may ask of a user
	// (AuthorizationServer.GroupClients).
	GroupClientsConfig   = config.GroupClientsConfig
	GroupClientScope     = config.GroupClientScope
	ResourceServerConfig = config.ResourceServerConfig
	ResourceConfig       = config.ResourceConfig
	OAuthGrantType       = config.OAuthGrantType
	// RemoteApplicationConfig declares one remote application
	// (Config.RemoteApplications).
	RemoteApplicationConfig = config.RemoteApplicationConfig
	// ProvisioningConfig pushes the accounts to SCIM 2.0 service providers
	// (Config.Provisioning).
	ProvisioningConfig = config.ProvisioningConfig
	ProvisioningTarget = config.ProvisioningTarget
	HTTPConfig         = config.HTTPConfig
)

// OAuth grant types a client may use (OAuthClientConfig.GrantTypes).
const (
	GrantAuthorizationCode = config.GrantAuthorizationCode
	GrantRefreshToken      = config.GrantRefreshToken
	GrantTokenExchange     = config.GrantTokenExchange
	GrantClientCredentials = config.GrantClientCredentials
	GrantJWTBearer         = config.GrantJWTBearer
)

// Config.Tenancy modes.
const (
	TenancySingle = config.TenancySingle
	TenancyMulti  = config.TenancyMulti
)
