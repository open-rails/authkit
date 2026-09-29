package authkit

import (
	"reflect"

	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/engine"
	"github.com/open-rails/authkit/internal/httpapi"
	"github.com/open-rails/authkit/internal/ratelimit"
)

// The one place public configuration becomes internal settings. Every
// exported field must be mapped; TestConfigMapping fails otherwise.

// settings is what New hands the internals: the engine's settings and, unless
// Config.HTTP is zero, the HTTP layer's.
type settings struct {
	engine engine.Config
	http   *httpapi.Config
}

func (c Config) settings() settings {
	s := settings{engine: engine.Config{
		River:                 engine.RiverConfig(c.River),
		Naming:                c.Naming,
		Token:                 engine.TokenConfig(c.Token),
		Frontend:              engine.FrontendConfig(c.Frontend),
		Registration:          engine.RegistrationConfig(c.Registration),
		Password:              engine.PasswordPolicy(c.Password),
		Username:              c.Username,
		Keys:                  engine.KeysConfig(c.Keys),
		Identity:              engine.IdentityConfig(c.Identity),
		APIKeys:               engine.APIKeysConfig(c.APIKeys),
		TwoFactor:             engine.TwoFactorConfig(c.TwoFactor),
		Passkeys:              engine.PasskeyConfig(c.Passkeys),
		DeviceKeys:            engine.DeviceKeysConfig(c.DeviceKeys),
		Roles:                 c.Roles.engine(),
		Applications:          engine.ApplicationsConfig(c.Applications),
		Delegated:             engine.DelegatedConfig(c.Delegated),
		Documents:             c.Documents.engine(),
		Schema:                c.Schema,
		SolanaNetwork:         c.SolanaNetwork,
		SessionEventRetention: c.SessionEventRetention,
	}}
	if !reflect.ValueOf(c.HTTP).IsZero() {
		h := c.HTTP.internal()
		s.http = &h
	}
	return s
}

func (c RoleConfig) engine() engine.RoleConfig {
	var out engine.RoleConfig
	if c.Personas != nil {
		out.Personas = make(map[string]engine.Persona, len(c.Personas))
		for name, p := range c.Personas {
			out.Personas[name] = engine.Persona{
				Permissions:        p.Permissions,
				RequireMFA:         p.RequireMFA,
				CustomRoles:        p.CustomRoles,
				APIKeys:            p.APIKeys,
				RemoteApplications: p.RemoteApplications,
			}
		}
	}
	for _, r := range c.Roles {
		out.Roles = append(out.Roles, engine.Role(r))
	}
	return out
}

func (c DocumentsConfig) engine() engine.DocumentsConfig {
	out := engine.DocumentsConfig{AllowRegisteredTier: c.AllowRegisteredTier}
	for _, r := range c.Readers {
		out.Readers = append(out.Readers, engine.DocumentReader(r))
	}
	return out
}

func (c HTTPConfig) internal() httpapi.Config {
	out := httpapi.Config{
		Mount: httpapi.MountOptions{
			Groups:        append([]iam.RouteGroup(nil), c.Groups...),
			BasePath:      c.BasePath,
			APIPath:       c.APIPath,
			Exclude:       append([]string(nil), c.Exclude...),
			Wrap:          c.Wrap,
			RefreshCookie: c.RefreshCookie,
		},
		DPoPRequestURL:      c.DPoPRequestURL,
		Redis:               c.Redis,
		RedisKeyPrefix:      c.RedisKeyPrefix,
		DisableRateLimiting: c.DisableRateLimiting,
		TrustedProxies:      append([]string(nil), c.TrustedProxies...),
		CloudflareProxies:   append([]string(nil), c.CloudflareProxies...),
		DirectPeerIP:        c.DirectPeerIP,
		ClientIP:            c.ClientIP,
		Languages:           httpapi.LanguageConfig{Supported: append([]string(nil), c.Languages.Supported...), Default: c.Languages.Default},
	}
	if c.Limiter != nil {
		out.Limiter = c.Limiter
	}
	if c.RateLimits != nil {
		out.RateLimits = make(map[string]ratelimit.Limit, len(c.RateLimits))
		for bucket, l := range c.RateLimits {
			out.RateLimits[bucket] = ratelimit.Limit{Limit: l.Limit, Window: l.Window, Cooldown: l.Cooldown}
		}
	}
	return out
}

func (d Deps) engine() engine.Deps {
	return engine.Deps{
		River:                  d.River.engine(),
		Postgres:               d.Postgres,
		Email:                  d.Email,
		SMS:                    d.SMS,
		Entitlements:           d.Entitlements,
		OnSoftDelete:           d.OnSoftDelete,
		OnHardDelete:           d.OnHardDelete,
		OnRestore:              d.OnRestore,
		OnEvent:                d.OnEvent,
		DelegatedAuthorization: d.DelegatedAuthorization,
		ApplicationAdmission:   d.ApplicationAdmission,
		NameAdmission:          d.NameAdmission,
		SolanaSNSResolver:      d.SolanaSNSResolver,
		OutboundHTTP:           d.OutboundHTTP,
		Clock:                  d.Clock,
	}
}

func (o MigrateOptions) engine() engine.MigrateOptions {
	return engine.MigrateOptions{
		Schema:      o.Schema,
		River:       o.River.engine(),
		RiverSchema: o.RiverSchema,
		RuntimePool: o.RuntimePool,
	}
}

func (o *RiverOwnership) engine() *engine.RiverOwnership {
	if o == nil || !o.fromHost {
		return nil
	}
	return engine.RiverFromHost()
}
