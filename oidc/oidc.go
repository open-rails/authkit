package oidckit

// NOTE: Implementation will use the zitadel/oidc RP helpers.
// We keep the initial API surface minimal so apps can start wiring.

// Provider identifies a configured OIDC provider.
type Provider string

const (
	ProviderGoogle  Provider = "google"
	ProviderGitHub  Provider = "github"
	ProviderDiscord Provider = "discord"
)

// Config holds per-provider client settings.
type Config struct {
	Issuer       string // Discovery URL
	ClientID     string
	ClientSecret string
	RedirectURI  string
	Scopes       []string
	// PKCE is always enabled; code_verifier is generated per request.
}
