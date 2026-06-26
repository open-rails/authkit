package authhttp

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"

	authkit "github.com/open-rails/authkit"
	"github.com/open-rails/authkit/embedded"
)

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

func (s *Service) capabilities() authkit.AuthCapabilities {
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
	return authkit.AuthCapabilities{
		Registration: authkit.AuthRegistrationCapabilities{
			Mode:                string(opts.NativeUserRegistrationMode),
			InviteTokenRequired: opts.NativeUserRegistrationMode == embedded.RegistrationModeInviteOnly,
		},
		Providers: s.providerSummaries(),
		Password: authkit.AuthPasswordCapabilities{
			Login: true,
		},
		Passwordless: authkit.AuthPasswordlessCapabilities{
			Enabled:  opts.PasswordlessLoginEnabled,
			Channels: channels,
		},
		Passkeys: authkit.AuthPasskeyCapabilities{
			Login: s.svc.PasskeysEnabled(),
		},
		Solana: authkit.AuthSolanaCapabilities{
			Login: opts.SolanaNetwork != "",
		},
		Verification: authkit.AuthVerificationCapabilities{
			Registration: string(cfg.Registration.Verification),
		},
		Languages: langs,
	}
}
