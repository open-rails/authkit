package authhttp

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"

	authkit "github.com/open-rails/authkit"
	"github.com/open-rails/authkit/embedded"
)

// AuthCapabilities is the public, static auth feature-discovery response.
type AuthCapabilities struct {
	Registration           AuthRegistrationCapabilities `json:"registration"`
	ExternalLoginProviders []AuthProviderSummary        `json:"external_login_providers"`
	Username               AuthUsernameCapabilities     `json:"username"`
	Password               AuthPasswordCapabilities     `json:"password"`
	Passwordless           AuthPasswordlessCapabilities `json:"passwordless"`
	Passkeys               AuthPasskeyCapabilities      `json:"passkeys"`
	Solana                 AuthSolanaCapabilities       `json:"solana"`
	Verification           AuthVerificationCapabilities `json:"verification"`
	Languages              []string                     `json:"languages,omitempty"`
}

type AuthRegistrationCapabilities struct {
	Mode                string `json:"mode"`
	InviteTokenRequired bool   `json:"invite_token_required"`
}

type AuthProviderSummary struct {
	ID                   string `json:"id"`
	Name                 string `json:"name"`
	SupportsLogin        bool   `json:"supports_login"`
	SupportsRegistration bool   `json:"supports_registration"`
	SupportsLink         bool   `json:"supports_link"`
}

// AuthUsernameCapabilities publishes the interactive username rule. Pattern is
// the fixed character rule; length is bounded separately.
type AuthUsernameCapabilities struct {
	MinLength int    `json:"min_length"`
	MaxLength int    `json:"max_length"`
	Pattern   string `json:"pattern"`
}

// AuthPasswordCapabilities publishes everything a browser needs to
// pre-validate a new password except the blocklist itself.
type AuthPasswordCapabilities struct {
	Login            bool `json:"login"`
	MinLength        int  `json:"min_length"`
	MaxLength        int  `json:"max_length"`
	RequireUppercase bool `json:"require_uppercase"`
	RequireLowercase bool `json:"require_lowercase"`
	RequireDigit     bool `json:"require_digit"`
	RequireSymbol    bool `json:"require_symbol"`
	RejectCommon     bool `json:"reject_common"`
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
			Mode:                string(cfg.Registration.NativeUserMode),
			InviteTokenRequired: cfg.Registration.NativeUserMode == embedded.RegistrationModeInviteOnly,
		},
		ExternalLoginProviders: s.providerSummaries(),
		Username: AuthUsernameCapabilities{
			MinLength: cfg.Username.MinLength,
			MaxLength: cfg.Username.MaxLength,
			Pattern:   authkit.UsernamePattern,
		},
		Password: AuthPasswordCapabilities{
			Login:            true,
			MinLength:        cfg.Password.MinLength,
			MaxLength:        cfg.Password.MaxLength,
			RequireUppercase: cfg.Password.RequireUppercase,
			RequireLowercase: cfg.Password.RequireLowercase,
			RequireDigit:     cfg.Password.RequireDigit,
			RequireSymbol:    cfg.Password.RequireSymbol,
			RejectCommon:     !cfg.Password.AllowCommon,
		},
		Passwordless: AuthPasswordlessCapabilities{
			Enabled:  cfg.Registration.PasswordlessLogin,
			Channels: channels,
		},
		Passkeys: AuthPasskeyCapabilities{
			Login: s.svc.PasskeysEnabled(),
		},
		Solana: AuthSolanaCapabilities{
			Login: cfg.SolanaNetwork != "",
		},
		Verification: AuthVerificationCapabilities{
			Registration: string(cfg.Registration.Verification),
		},
		Languages: langs,
	}
}
