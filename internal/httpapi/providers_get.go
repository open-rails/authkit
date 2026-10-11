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

func (s *Service) handleCapabilitiesGET(w http.ResponseWriter, r *http.Request) {
	caps := s.Capabilities()
	layout := layoutFrom(r)
	caps.Paths = MountPaths{API: layout.api, OIDC: nullableString(layout.oidc), JWKS: nullableString(layout.jwks)}
	body, _ := json.Marshal(caps)
	sum := sha256.Sum256(body)
	w.Header().Set("Cache-Control", "public, max-age=300")
	w.Header().Set("ETag", `"`+hex.EncodeToString(sum[:])+`"`)
	writeJSON(w, http.StatusOK, caps)
}

func (s *Service) Capabilities() Capabilities {
	cfg := s.cfg
	email, sms := s.svc.EmailAvailable(), s.svc.SMSAvailable()
	channels := []string{}
	if email {
		channels = append(channels, "email")
	}
	if sms {
		channels = append(channels, "sms")
	}
	return Capabilities{
		DPoP: string(cfg.SignIn.DPoP),
		Registration: RegistrationCapabilities{
			Mode:                string(cfg.Registration.NativeUserMode),
			InviteTokenRequired: cfg.Registration.NativeUserMode == iam.RegistrationModeInviteOnly,
			Agreements:          nonNil(cfg.Registration.Agreements),
		},
		Agreements:             s.svc.Agreements(),
		ExternalLoginProviders: s.providerSummaries(),
		Username: UsernameCapabilities{
			MinLength:             cfg.Username.MinLength,
			MaxLength:             cfg.Username.MaxLength,
			Pattern:               naming.UsernamePattern,
			Renames:               cfg.Username.Renames,
			RenameIntervalSeconds: int64(naming.Cooldown(cfg.Username) / time.Second),
			FormerNames:           naming.NewState(cfg.Username, nil, time.Time{}).Policy,
		},
		Password: PasswordCapabilities{
			MinLength:        cfg.Password.MinLength,
			MaxLength:        cfg.Password.MaxLength,
			RequireUppercase: cfg.Password.RequireUppercase,
			RequireLowercase: cfg.Password.RequireLowercase,
			RequireDigit:     cfg.Password.RequireDigit,
			RequireSymbol:    cfg.Password.RequireSymbol,
			AllowCommon:      cfg.Password.AllowCommon,
		},
		Passwordless: PasswordlessCapabilities{
			Enabled:  cfg.Registration.PasswordlessLogin,
			Channels: channels,
		},
		Passkeys: PasskeyCapabilities{
			Login: s.svc.PasskeysEnabled(),
		},
		Solana: SolanaCapabilities{
			Login: cfg.SolanaNetwork != "",
		},
		Verification: VerificationCapabilities{
			Registration: string(cfg.Registration.Verification),
		},
		Channels:    ChannelCapabilities{Email: email, SMS: sms},
		SMS:         SMSCapabilities{Countries: nonNil(cfg.SMS.AllowedCountries)},
		TwoFactor:   TwoFactorCapabilities{Mode: cfg.TwoFactor.Mode, Methods: s.svc.TwoFactorMethods()},
		Invitations: InvitationCapabilities{Enabled: !cfg.Invitations.Disabled},
		Languages:   cfg.Languages.Supported,
	}
}

// nonNil is v, or an empty list for nil: the wire's lists are never null.
func nonNil[T any](v []T) []T {
	if v == nil {
		return []T{}
	}
	return v
}
