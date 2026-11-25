package httpapi

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"time"

	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/config"
	"github.com/open-rails/authkit/internal/naming"
	policy "github.com/open-rails/authkit/naming"
)

func (s *Service) handleCapabilitiesGET(w http.ResponseWriter, r *http.Request) {
	caps := s.Capabilities()
	layout := layoutFrom(r)
	caps.Paths = MountPaths{API: layout.api, OIDC: nullableString(layout.oidc), JWKS: nullableString(layout.jwks)}
	body, _ := json.Marshal(caps)
	sum := sha256.Sum256(body)
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
	var captcha *iam.CaptchaWidget
	if s.captcha != nil {
		w := s.captcha.Widget()
		captcha = &w
	}
	return Capabilities{
		Captcha:       captcha,
		Notifications: true,
		DPoP:          "required",
		Registration: RegistrationCapabilities{
			Mode:                string(cfg.Registration),
			InviteTokenRequired: cfg.Registration == iam.RegistrationModeInviteOnly,
			Agreements:          nonNil(config.SignUpAgreements(cfg)),
		},
		Agreements:             s.svc.Agreements(),
		ExternalLoginProviders: s.providerSummaries(),
		Username: UsernameCapabilities{
			MinLength:             naming.MinLength,
			MaxLength:             naming.MaxLength,
			Pattern:               naming.UsernamePattern,
			Renames:               true,
			RenameIntervalSeconds: int64(policy.RenameCooldown / time.Second),
			FormerNames:           naming.Policy,
		},
		Password: PasswordCapabilities{MinLength: config.PasswordMinLength, MaxLength: config.PasswordMaxLength},
		Passwordless: PasswordlessCapabilities{
			Enabled:  config.Mounted(cfg, iam.RoutePasswordless),
			Channels: channels,
		},
		Passkeys: PasskeyCapabilities{
			Login: s.svc.PasskeysEnabled(),
		},
		Solana: SolanaCapabilities{
			Login: cfg.SolanaNetwork != "",
		},
		Verification: VerificationCapabilities{
			Registration: string(iam.RegistrationVerificationRequired),
		},
		Channels:    ChannelCapabilities{Email: email, SMS: sms},
		SMS:         SMSCapabilities{Countries: nonNil(cfg.SMSCountries)},
		TwoFactor:   TwoFactorCapabilities{Mode: cfg.TwoFactor, Methods: s.svc.TwoFactorMethods()},
		Invitations: InvitationCapabilities{Enabled: config.InvitationsOn(cfg)},
		Languages:   cfg.Languages,
	}
}

// nonNil is v, or an empty list for nil: the wire's lists are never null.
func nonNil[T any](v []T) []T {
	if v == nil {
		return []T{}
	}
	return v
}
