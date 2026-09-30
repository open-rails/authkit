package httpapi

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"time"

	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/naming"
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
	Channels               AuthChannelCapabilities      `json:"channels"`
	Languages              []string                     `json:"languages,omitempty"`
	Paths                  AuthPaths                    `json:"paths"`
}

// AuthPaths are the serving mount's anchors as full paths, so a client that
// knows one AuthKit URL finds the rest. Unmounted anchors are omitted.
type AuthPaths struct {
	API  string `json:"api"`
	OIDC string `json:"oidc,omitempty"`
	JWKS string `json:"jwks,omitempty"`
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
// the fixed character rule; length is bounded separately. Renames says
// whether users may rename themselves, and how often.
type AuthUsernameCapabilities struct {
	MinLength             int               `json:"min_length"`
	MaxLength             int               `json:"max_length"`
	Pattern               string            `json:"pattern"`
	Renames               bool              `json:"renames"`
	RenameIntervalSeconds int64             `json:"rename_interval_seconds"`
	FormerNames           naming.PolicyInfo `json:"former_names"`
}

// AuthChannelCapabilities says which contact channels can deliver now: a
// sender is configured and, for SMS, its latest health check passed.
type AuthChannelCapabilities struct {
	Email bool `json:"email"`
	SMS   bool `json:"sms"`
}

// AuthPasswordCapabilities publishes everything a browser needs to
// pre-validate a new password except the blocklist itself.
type AuthPasswordCapabilities struct {
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

func (s *Service) handleCapabilitiesGET(w http.ResponseWriter, r *http.Request) {
	caps := s.Capabilities()
	layout := layoutFrom(r)
	caps.Paths = AuthPaths{API: layout.api, OIDC: layout.oidc, JWKS: layout.jwks}
	body, _ := json.Marshal(caps)
	sum := sha256.Sum256(body)
	w.Header().Set("Cache-Control", "public, max-age=300")
	w.Header().Set("ETag", `"`+hex.EncodeToString(sum[:])+`"`)
	writeJSON(w, http.StatusOK, caps)
}

func (s *Service) Capabilities() AuthCapabilities {
	cfg := s.cfg
	channels := []string{"email"}
	if s.SMSAvailable() {
		channels = append(channels, "sms")
	}
	return AuthCapabilities{
		Registration: AuthRegistrationCapabilities{
			Mode:                string(cfg.Registration.NativeUserMode),
			InviteTokenRequired: cfg.Registration.NativeUserMode == iam.RegistrationModeInviteOnly,
		},
		ExternalLoginProviders: s.providerSummaries(),
		Username: AuthUsernameCapabilities{
			MinLength:             cfg.Username.MinLength,
			MaxLength:             cfg.Username.MaxLength,
			Pattern:               naming.UsernamePattern,
			Renames:               cfg.Username.Renames,
			RenameIntervalSeconds: int64(naming.Cooldown(cfg.Username) / time.Second),
			FormerNames:           naming.NewState(cfg.Username, nil, time.Time{}).Policy,
		},
		Password: AuthPasswordCapabilities{
			MinLength:        cfg.Password.MinLength,
			MaxLength:        cfg.Password.MaxLength,
			RequireUppercase: cfg.Password.RequireUppercase,
			RequireLowercase: cfg.Password.RequireLowercase,
			RequireDigit:     cfg.Password.RequireDigit,
			RequireSymbol:    cfg.Password.RequireSymbol,
			RejectCommon:     cfg.Password.RejectCommon,
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
		Channels:  AuthChannelCapabilities{Email: s.svc.HasEmailSender(), SMS: s.SMSAvailable()},
		Languages: cfg.Languages.Supported,
	}
}
