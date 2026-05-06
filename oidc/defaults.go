package oidckit

import "context"

// RPConfig describes an IdP (Relying Party) with minimal fields.
// If ClientSecret is empty and SecretProvider is set, the manager will call it
// to obtain a short‑lived client_secret (e.g., Apple’s ES256 JWT).
type RPConfig struct {
	ClientID     string
	ClientSecret string
	// Optional: dynamic secret minting
	SecretProvider func(ctx context.Context) (string, error)
	// Optional: additional/override scopes. "openid" will be ensured.
	Scopes []string
}

// DefaultsFor returns an internal RPClient for a known provider name.
func DefaultsFor(name string) (RPClient, bool) {
	switch name {
	case "google":
		return RPClient{
			Issuer:       "https://accounts.google.com",
			Scopes:       []string{"openid", "email", "profile"},
			ClientID:     "",
			ClientSecret: "",
		}, true
	case "apple":
		return RPClient{
			Issuer:       "https://appleid.apple.com",
			Scopes:       []string{"openid", "email", "name"},
			ClientID:     "",
			ClientSecret: "",
			// Apple commonly uses form_post for web flows; set explicitly.
			ExtraAuthParams: map[string]string{"response_mode": "form_post"},
		}, true
	case "discord":
		// Discord is OAuth2 (non‑OIDC). We expose minimal defaults (scopes) so callers
		// can provide ClientID/Secret and authkit’s Discord OAuth handlers will work.
		return RPClient{
			Issuer:       "https://discord.com",
			Scopes:       []string{"identify", "email"},
			ClientID:     "",
			ClientSecret: "",
		}, true
	default:
		return RPClient{}, false
	}
}

// NewManagerFromMinimal builds a Manager from minimal provider settings.
func NewManagerFromMinimal(min map[string]RPConfig) *Manager {
	cfgs := make(map[string]RPClient, len(min))
	for name, m := range min {
		if base, ok := DefaultsFor(name); ok {
			base.ClientID = m.ClientID
			base.ClientSecret = m.ClientSecret
			// Wire dynamic secret provider if present
			base.ClientSecretProvider = m.SecretProvider
			if len(m.Scopes) > 0 {
				base.Scopes = mergeScopes(base.Scopes, m.Scopes)
			}
			if name != "discord" {
				base.Scopes = ensureOpenID(base.Scopes)
			}
			cfgs[name] = base
		}
	}
	return NewManager(cfgs)
}

func ensureOpenID(scopes []string) []string {
	for _, s := range scopes {
		if s == "openid" {
			return scopes
		}
	}
	return append(scopes, "openid")
}

func mergeScopes(base, extra []string) []string {
	set := map[string]struct{}{}
	for _, s := range base {
		set[s] = struct{}{}
	}
	for _, s := range extra {
		set[s] = struct{}{}
	}
	out := make([]string, 0, len(set))
	for s := range set {
		out = append(out, s)
	}
	return out
}
