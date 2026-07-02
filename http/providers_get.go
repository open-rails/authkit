package authhttp

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"

	"github.com/open-rails/authkit/embedded"
)

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

func (s *Service) handleProvidersGET(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"providers": s.providerSummaries(),
	})
}

func (s *Service) handleCapabilitiesGET(w http.ResponseWriter, _ *http.Request) {
	caps := s.capabilities()
	body, _ := json.Marshal(caps)
	sum := sha256.Sum256(body)
	w.Header().Set("Cache-Control", "public, max-age=300")
	w.Header().Set("ETag", `"`+hex.EncodeToString(sum[:])+`"`)
	writeJSON(w, http.StatusOK, caps)
}

func (s *Service) capabilities() AuthCapabilities {
	cfg := s.svc.Config()
	opts := s.svc.Options()
	langs := []string(nil)
	if s.langCfg != nil {
		langs = append(langs, s.langCfg.Supported...)
	}
	channels := []string{"email"}
	if s.SMSAvailable() {
		channels = append(channels, "sms")
	}
	return AuthCapabilities{
		Registration: AuthRegistrationCapabilities{
			Mode:                string(opts.NativeUserRegistrationMode),
			InviteTokenRequired: opts.NativeUserRegistrationMode == embedded.RegistrationModeInviteOnly,
		},
		Providers: s.providerSummaries(),
		Password: AuthPasswordCapabilities{
			Login: true,
		},
		Passwordless: AuthPasswordlessCapabilities{
			Enabled:  opts.PasswordlessLoginEnabled,
			Channels: channels,
		},
		Passkeys: AuthPasskeyCapabilities{
			Login: s.svc.PasskeysEnabled(),
		},
		Solana: AuthSolanaCapabilities{
			Login: opts.SolanaNetwork != "",
		},
		Verification: AuthVerificationCapabilities{
			Registration: string(cfg.Registration.Verification),
		},
		Languages: langs,
	}
}
