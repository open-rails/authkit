package authkit

// AuthCapabilities is the public, static auth feature-discovery response.
type AuthCapabilities struct {
	Registration AuthRegistrationCapabilities `json:"registration"`
	Providers    []AuthProviderSummary        `json:"providers"`
	Password     AuthPasswordCapabilities     `json:"password"`
	Passwordless AuthPasswordlessCapabilities `json:"passwordless"`
	Passkeys     AuthPasskeyCapabilities      `json:"passkeys"`
	Solana       AuthSolanaCapabilities       `json:"solana"`
	Verification AuthVerificationCapabilities `json:"verification"`
	Languages    []string                     `json:"languages,omitempty"`
}

type AuthRegistrationCapabilities struct {
	Mode                string `json:"mode"`
	InviteTokenRequired bool   `json:"invite_token_required"`
}

type AuthProviderSummary struct {
	ID                   string `json:"id"`
	Name                 string `json:"name"`
	Kind                 string `json:"kind"`
	SupportsLogin        bool   `json:"supports_login"`
	SupportsRegistration bool   `json:"supports_registration"`
	SupportsLink         bool   `json:"supports_link"`
}

type AuthPasswordCapabilities struct {
	Login bool `json:"login"`
}

type AuthPasswordlessCapabilities struct {
	Enabled  bool     `json:"enabled"`
	Channels []string `json:"channels,omitempty"`
}

type AuthPasskeyCapabilities struct {
	Login bool `json:"login"`
}

type AuthSolanaCapabilities struct {
	Login bool `json:"login"`
}

type AuthVerificationCapabilities struct {
	Registration string `json:"registration"`
}

// PersonaCapabilities are opt-in generated management capabilities for a persona.
type PersonaCapabilities struct {
	APIKeys            bool
	RemoteApplications bool
	CustomRoles        bool
}
