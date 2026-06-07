package twilio

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	core "github.com/open-rails/authkit/core"
	authlang "github.com/open-rails/authkit/lang"
)

const messagesURLFormat = "https://api.twilio.com/2010-04-01/Accounts/%s/Messages.json"

// VerificationBuilder renders a verification SMS body.
type VerificationBuilder func(ctx context.Context, phone string, msg core.VerificationMessage, verificationURL string) string

// PasswordResetBuilder renders a password reset SMS body.
type PasswordResetBuilder func(ctx context.Context, phone, token, resetURL string) string

// LoginCodeBuilder renders a login code SMS body.
type LoginCodeBuilder func(ctx context.Context, phone, code string) string

// Config configures the Twilio Messaging API SMS adapter.
type Config struct {
	AccountSID          string
	AuthToken           string
	MessagingServiceSID string
	AppName             string
	Client              *http.Client

	VerificationLinkURL func(token string) string
	ResetLinkURL        func(token string) string

	VerificationBuilder  VerificationBuilder
	PasswordResetBuilder PasswordResetBuilder
	LoginCodeBuilder     LoginCodeBuilder
}

// Sender sends SMS messages via Twilio Messaging API.
type Sender struct {
	AccountSID          string
	AuthToken           string
	MessagingServiceSID string
	AppName             string
	Client              *http.Client

	VerificationLinkURL func(token string) string
	ResetLinkURL        func(token string) string

	VerificationBuilder  VerificationBuilder
	PasswordResetBuilder PasswordResetBuilder
	LoginCodeBuilder     LoginCodeBuilder
}

// New creates a validated Twilio Messaging sender.
func New(cfg Config) (*Sender, error) {
	accountSID := strings.TrimSpace(cfg.AccountSID)
	authToken := strings.TrimSpace(cfg.AuthToken)
	messagingServiceSID := strings.TrimSpace(cfg.MessagingServiceSID)
	if accountSID == "" {
		return nil, fmt.Errorf("twilio account SID is required")
	}
	if authToken == "" {
		return nil, fmt.Errorf("twilio auth token is required")
	}
	if messagingServiceSID == "" {
		return nil, fmt.Errorf("twilio messaging service SID is required")
	}
	return &Sender{
		AccountSID:           accountSID,
		AuthToken:            authToken,
		MessagingServiceSID:  messagingServiceSID,
		AppName:              strings.TrimSpace(cfg.AppName),
		Client:               cfg.Client,
		VerificationLinkURL:  cfg.VerificationLinkURL,
		ResetLinkURL:         cfg.ResetLinkURL,
		VerificationBuilder:  cfg.VerificationBuilder,
		PasswordResetBuilder: cfg.PasswordResetBuilder,
		LoginCodeBuilder:     cfg.LoginCodeBuilder,
	}, nil
}

func (s *Sender) httpClient() *http.Client {
	if s.Client != nil {
		return s.Client
	}
	return &http.Client{Timeout: 10 * time.Second}
}

func (s *Sender) SendVerification(ctx context.Context, phone string, msg core.VerificationMessage) error {
	if err := msg.Validate(); err != nil {
		return err
	}
	link := ""
	if strings.TrimSpace(msg.LinkToken) != "" {
		link = strings.TrimSpace(msg.LinkToken)
		if s.VerificationLinkURL != nil {
			if built := strings.TrimSpace(s.VerificationLinkURL(link)); built != "" {
				link = built
			}
		}
	}
	if s.VerificationBuilder != nil {
		return s.sendMessage(ctx, phone, s.VerificationBuilder(ctx, phone, msg, link))
	}

	return s.sendMessage(ctx, phone, defaultVerificationBody(ctx, s.appLabel(), msg, link))
}

func (s *Sender) SendPasswordResetLink(ctx context.Context, phone, token string) error {
	linkOrToken := strings.TrimSpace(token)
	if s.ResetLinkURL != nil {
		if built := strings.TrimSpace(s.ResetLinkURL(linkOrToken)); built != "" {
			linkOrToken = built
		}
	}
	if s.PasswordResetBuilder != nil {
		return s.sendMessage(ctx, phone, s.PasswordResetBuilder(ctx, phone, token, linkOrToken))
	}
	body := defaultPasswordResetBody(ctx, s.appLabel(), linkOrToken)
	return s.sendMessage(ctx, phone, body)
}

func (s *Sender) SendLoginCode(ctx context.Context, phone, code string) error {
	if s.LoginCodeBuilder != nil {
		return s.sendMessage(ctx, phone, s.LoginCodeBuilder(ctx, phone, code))
	}
	body := defaultLoginCodeBody(ctx, s.appLabel(), strings.TrimSpace(code))
	return s.sendMessage(ctx, phone, body)
}

func (s *Sender) appLabel() string {
	if strings.TrimSpace(s.AppName) != "" {
		return strings.TrimSpace(s.AppName)
	}
	return "Auth"
}

func contextLanguage(ctx context.Context) string {
	locale, ok := authlang.LanguageFromContext(ctx)
	if !ok {
		return "en"
	}
	locale = strings.ToLower(strings.TrimSpace(strings.ReplaceAll(locale, "_", "-")))
	if locale == "" {
		return "en"
	}
	if i := strings.Index(locale, "-"); i > 0 {
		locale = locale[:i]
	}
	switch locale {
	case "es":
		return "es"
	default:
		return "en"
	}
}

func defaultVerificationBody(ctx context.Context, app string, msg core.VerificationMessage, link string) string {
	parts := make([]string, 0, 2)
	if strings.TrimSpace(msg.Code) != "" {
		if contextLanguage(ctx) == "es" {
			parts = append(parts, fmt.Sprintf("%s codigo de verificacion: %s", app, strings.TrimSpace(msg.Code)))
		} else {
			parts = append(parts, fmt.Sprintf("%s verification code: %s", app, strings.TrimSpace(msg.Code)))
		}
	}
	if strings.TrimSpace(link) != "" {
		if contextLanguage(ctx) == "es" {
			parts = append(parts, "Verificar: "+strings.TrimSpace(link))
		} else {
			parts = append(parts, "Verify: "+strings.TrimSpace(link))
		}
	}
	return strings.Join(parts, "\n")
}

func defaultPasswordResetBody(ctx context.Context, app, linkOrToken string) string {
	if contextLanguage(ctx) == "es" {
		return fmt.Sprintf("%s restablecer contrasena: %s", app, linkOrToken)
	}
	return fmt.Sprintf("%s password reset: %s", app, linkOrToken)
}

func defaultLoginCodeBody(ctx context.Context, app, code string) string {
	if contextLanguage(ctx) == "es" {
		return fmt.Sprintf("%s codigo de inicio: %s", app, code)
	}
	return fmt.Sprintf("%s login code: %s", app, code)
}

func (s *Sender) sendMessage(ctx context.Context, to, body string) error {
	if s == nil {
		return fmt.Errorf("SMS sender is nil")
	}
	if strings.TrimSpace(s.AccountSID) == "" || strings.TrimSpace(s.AuthToken) == "" {
		return fmt.Errorf("twilio account credentials are required")
	}
	if strings.TrimSpace(s.MessagingServiceSID) == "" {
		return fmt.Errorf("twilio messaging service SID is required")
	}
	if strings.TrimSpace(to) == "" {
		return fmt.Errorf("phone is required")
	}
	if strings.TrimSpace(body) == "" {
		return fmt.Errorf("message body is required")
	}

	apiURL := fmt.Sprintf(messagesURLFormat, strings.TrimSpace(s.AccountSID))
	formData := url.Values{}
	formData.Set("To", strings.TrimSpace(to))
	formData.Set("Body", strings.TrimSpace(body))
	formData.Set("MessagingServiceSid", strings.TrimSpace(s.MessagingServiceSID))

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, apiURL, strings.NewReader(formData.Encode()))
	if err != nil {
		return err
	}
	g := strings.TrimSpace(s.AccountSID)
	req.SetBasicAuth(g, strings.TrimSpace(s.AuthToken))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := s.httpClient().Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return nil
	}

	var errResp struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&errResp); err == nil {
		if errResp.Code != 0 || strings.TrimSpace(errResp.Message) != "" {
			return fmt.Errorf("twilio messaging error %d: %s", errResp.Code, errResp.Message)
		}
	}
	return fmt.Errorf("twilio messaging error: status %d", resp.StatusCode)
}
