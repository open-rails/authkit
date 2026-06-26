package twilio

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/open-rails/authkit/embedded"
	authlang "github.com/open-rails/authkit/lang"
)

const messagesURLFormat = "https://api.twilio.com/2010-04-01/Accounts/%s/Messages.json"

// VerificationBuilder renders a verification SMS body.
type VerificationBuilder func(ctx context.Context, phone string, msg embedded.VerificationMessage) string

// PasswordResetBuilder renders a password reset SMS body.
type PasswordResetBuilder func(ctx context.Context, phone, resetURL string) string

// LoginCodeBuilder renders a login code SMS body.
type LoginCodeBuilder func(ctx context.Context, phone, code string) string

// Config configures the Twilio Messaging API SMS adapter.
type Config struct {
	AccountSID          string
	AuthToken           string
	MessagingServiceSID string
	AppName             string
	Client              *http.Client

	VerificationBuilder  VerificationBuilder
	PasswordResetBuilder PasswordResetBuilder
	LoginCodeBuilder     LoginCodeBuilder

	// DeliveryPollInterval is the gap between status polls (default 750ms).
	DeliveryPollInterval time.Duration
}

// deliveryConfirmTimeout is the FIXED internal synchronous delivery-confirm
// window: after Twilio accepts a message, the sender polls its status until a
// terminal state (or this elapses) so delivery failures (e.g. error 30032 for an
// unverified toll-free sender) surface as errors instead of silent enqueues. Not
// host-configurable (#143).
const deliveryConfirmTimeout = 12 * time.Second

// Sender sends SMS messages via Twilio Messaging API.
type Sender struct {
	AccountSID          string
	AuthToken           string
	MessagingServiceSID string
	AppName             string
	Client              *http.Client

	VerificationBuilder  VerificationBuilder
	PasswordResetBuilder PasswordResetBuilder
	LoginCodeBuilder     LoginCodeBuilder

	DeliveryPollInterval time.Duration
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
		VerificationBuilder:  cfg.VerificationBuilder,
		PasswordResetBuilder: cfg.PasswordResetBuilder,
		LoginCodeBuilder:     cfg.LoginCodeBuilder,
		DeliveryPollInterval: cfg.DeliveryPollInterval,
	}, nil
}

func (s *Sender) httpClient() *http.Client {
	if s.Client != nil {
		return s.Client
	}
	return &http.Client{Timeout: 10 * time.Second}
}

func (s *Sender) SendVerification(ctx context.Context, phone string, msg embedded.VerificationMessage) error {
	if err := msg.Validate(); err != nil {
		return err
	}
	if s.VerificationBuilder != nil {
		return s.sendMessage(ctx, phone, s.VerificationBuilder(ctx, phone, msg))
	}

	return s.sendMessage(ctx, phone, defaultVerificationBody(ctx, s.appLabel(), msg))
}

func (s *Sender) SendPasswordResetLink(ctx context.Context, phone, resetURL string) error {
	resetURL = strings.TrimSpace(resetURL)
	if s.PasswordResetBuilder != nil {
		return s.sendMessage(ctx, phone, s.PasswordResetBuilder(ctx, phone, resetURL))
	}
	body := defaultPasswordResetBody(ctx, s.appLabel(), resetURL)
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
	language, ok := authlang.LanguageFromContext(ctx)
	if !ok {
		return "en"
	}
	language = strings.ToLower(strings.TrimSpace(strings.ReplaceAll(language, "_", "-")))
	if language == "" {
		return "en"
	}
	if i := strings.Index(language, "-"); i > 0 {
		language = language[:i]
	}
	switch language {
	case "es":
		return "es"
	default:
		return "en"
	}
}

func defaultVerificationBody(ctx context.Context, app string, msg embedded.VerificationMessage) string {
	parts := make([]string, 0, 2)
	if strings.TrimSpace(msg.Code) != "" {
		action := "verification"
		if strings.TrimSpace(msg.Purpose) == "contact_change" {
			action = "change confirmation"
		}
		if contextLanguage(ctx) == "es" {
			if action == "change confirmation" {
				parts = append(parts, fmt.Sprintf("%s codigo de confirmacion: %s", app, strings.TrimSpace(msg.Code)))
			} else {
				parts = append(parts, fmt.Sprintf("%s codigo de verificacion: %s", app, strings.TrimSpace(msg.Code)))
			}
		} else {
			parts = append(parts, fmt.Sprintf("%s %s code: %s", app, action, strings.TrimSpace(msg.Code)))
		}
	}
	if strings.TrimSpace(msg.LinkURL) != "" {
		if contextLanguage(ctx) == "es" {
			parts = append(parts, "Verificar: "+strings.TrimSpace(msg.LinkURL))
		} else {
			parts = append(parts, "Verify: "+strings.TrimSpace(msg.LinkURL))
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
		// Parse the created message so we can (optionally) confirm delivery
		// synchronously instead of trusting the "accepted" enqueue response.
		var created messageResource
		_ = json.NewDecoder(resp.Body).Decode(&created)
		return s.confirmDelivery(ctx, created)
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

// messageResource is the subset of a Twilio Message we read from create/fetch.
type messageResource struct {
	SID          string `json:"sid"`
	Status       string `json:"status"`
	ErrorCode    *int   `json:"error_code"`
	ErrorMessage string `json:"error_message"`
}

// terminal delivery states.
func isDeliverySuccess(status string) bool {
	switch strings.ToLower(strings.TrimSpace(status)) {
	case "delivered", "sent", "received":
		return true
	}
	return false
}

func isDeliveryFailure(status string) bool {
	switch strings.ToLower(strings.TrimSpace(status)) {
	case "undelivered", "failed", "canceled":
		return true
	}
	return false
}

func deliveryFailureError(m messageResource) error {
	code := 0
	if m.ErrorCode != nil {
		code = *m.ErrorCode
	}
	detail := strings.TrimSpace(m.ErrorMessage)
	if detail == "" {
		detail = twilioErrorHint(code)
	}
	return fmt.Errorf("twilio SMS not delivered (status=%s, error_code=%d): %s", m.Status, code, detail)
}

// twilioErrorHint adds a human hint for the most common silent-undelivered codes.
func twilioErrorHint(code int) string {
	switch code {
	case 30032:
		return "toll-free number is not verified (complete Twilio toll-free verification)"
	case 30034:
		return "A2P 10DLC campaign is not registered/approved for this number"
	case 30007:
		return "message filtered/blocked by carrier"
	case 21408, 21211:
		return "destination number is not permitted or invalid"
	default:
		return "see Twilio message error code"
	}
}

// confirmDelivery polls the message status until it reaches a terminal state or
// the configured timeout elapses. It returns an error only when delivery has
// definitively failed; a timeout with the message still in flight is treated as
// success (the code may still arrive) so we never block a working send.
func (s *Sender) confirmDelivery(ctx context.Context, created messageResource) error {
	if isDeliveryFailure(created.Status) {
		return deliveryFailureError(created)
	}
	if isDeliverySuccess(created.Status) {
		return nil
	}
	if strings.TrimSpace(created.SID) == "" {
		return nil // cannot poll without a SID; do not block
	}

	interval := s.DeliveryPollInterval
	if interval <= 0 {
		interval = 750 * time.Millisecond
	}
	deadline := time.Now().Add(deliveryConfirmTimeout)

	for {
		select {
		case <-ctx.Done():
			return nil // caller gave up; do not turn cancellation into a failure
		case <-time.After(interval):
		}

		m, err := s.fetchMessage(ctx, created.SID)
		if err != nil {
			// Transient fetch error: keep trying until the deadline, then pass.
			if time.Now().After(deadline) {
				return nil
			}
			continue
		}
		if isDeliveryFailure(m.Status) {
			return deliveryFailureError(m)
		}
		if isDeliverySuccess(m.Status) {
			return nil
		}
		if time.Now().After(deadline) {
			return nil // still in flight at timeout; treat as accepted
		}
	}
}

// fetchMessage reads the current state of a previously created message.
func (s *Sender) fetchMessage(ctx context.Context, sid string) (messageResource, error) {
	var m messageResource
	apiURL := fmt.Sprintf("https://api.twilio.com/2010-04-01/Accounts/%s/Messages/%s.json",
		strings.TrimSpace(s.AccountSID), strings.TrimSpace(sid))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiURL, nil)
	if err != nil {
		return m, err
	}
	req.SetBasicAuth(strings.TrimSpace(s.AccountSID), strings.TrimSpace(s.AuthToken))
	resp, err := s.httpClient().Do(req)
	if err != nil {
		return m, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return m, fmt.Errorf("twilio message fetch status %d", resp.StatusCode)
	}
	if err := json.NewDecoder(resp.Body).Decode(&m); err != nil {
		return m, err
	}
	return m, nil
}
