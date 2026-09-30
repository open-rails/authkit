package twilio

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/open-rails/authkit/iam"
)

const (
	messagesURLFormat = "https://api.twilio.com/2010-04-01/Accounts/%s/Messages.json"
	messageURLFormat  = "https://api.twilio.com/2010-04-01/Accounts/%s/Messages/%s.json"

	// deliveryConfirmTimeout is the fixed window Send polls an accepted message
	// for a terminal status, so delivery failures (e.g. error 30032 for an
	// unverified toll-free sender) surface as errors instead of silent enqueues.
	deliveryConfirmTimeout = 12 * time.Second
	defaultPollInterval    = 750 * time.Millisecond
)

// SMSConfig configures NewSMS. AccountSID, AuthToken and MessagingServiceSID
// are required.
type SMSConfig struct {
	AccountSID          string
	AuthToken           string
	MessagingServiceSID string
	// AppName names the app in the built-in copy (default "Auth").
	AppName string
	// Client sends the API requests (default: a 10s-timeout client).
	Client *http.Client
	// DeliveryPollInterval is the gap between delivery status polls (default
	// 750ms).
	DeliveryPollInterval time.Duration
	// Render returns the body for msg, or false to use the built-in template
	// for msg.Kind.
	Render func(ctx context.Context, msg iam.SMSMessage) (string, bool)
}

// SMS delivers AuthKit's text messages through the Twilio Messaging API and
// confirms delivery before Send returns.
type SMS struct {
	accountSID          string
	authToken           string
	messagingServiceSID string
	app                 string
	client              *http.Client
	pollInterval        time.Duration
	render              func(context.Context, iam.SMSMessage) (string, bool)
}

// NewSMS validates cfg and returns an SMS.
func NewSMS(cfg SMSConfig) (*SMS, error) {
	accountSID := strings.TrimSpace(cfg.AccountSID)
	authToken := strings.TrimSpace(cfg.AuthToken)
	messagingServiceSID := strings.TrimSpace(cfg.MessagingServiceSID)
	if accountSID == "" {
		return nil, errors.New("twilio account SID is required")
	}
	if authToken == "" {
		return nil, errors.New("twilio auth token is required")
	}
	if messagingServiceSID == "" {
		return nil, errors.New("twilio messaging service SID is required")
	}
	poll := cfg.DeliveryPollInterval
	if poll <= 0 {
		poll = defaultPollInterval
	}
	return &SMS{
		accountSID:          accountSID,
		authToken:           authToken,
		messagingServiceSID: messagingServiceSID,
		app:                 appLabel(cfg.AppName),
		client:              httpClient(cfg.Client),
		pollInterval:        poll,
		render:              cfg.Render,
	}, nil
}

// Send renders msg (Render, else the built-in template for msg.Kind), sends it
// and waits up to 12s for a delivery verdict: a definite failure is an error, a
// message still in flight is not. Wire it as authkit.Deps.SMS.
func (s *SMS) Send(ctx context.Context, msg iam.SMSMessage) error {
	to := strings.TrimSpace(msg.To)
	if to == "" {
		return errors.New("phone is required")
	}
	if msg.Kind == iam.MessageVerification {
		if err := validateVerification(msg.Code, msg.Link); err != nil {
			return err
		}
	}
	var (
		body string
		ok   bool
	)
	if s.render != nil {
		body, ok = s.render(ctx, msg)
	}
	if !ok {
		var err error
		if body, err = smsTemplate(s.app, msg); err != nil {
			return err
		}
	}
	return s.deliver(ctx, to, body)
}

func (s *SMS) deliver(ctx context.Context, to, body string) error {
	body = strings.TrimSpace(body)
	if body == "" {
		return errors.New("message body is required")
	}

	form := url.Values{}
	form.Set("To", to)
	form.Set("Body", body)
	form.Set("MessagingServiceSid", s.messagingServiceSID)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, fmt.Sprintf(messagesURLFormat, s.accountSID), strings.NewReader(form.Encode()))
	if err != nil {
		return err
	}
	req.SetBasicAuth(s.accountSID, s.authToken)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := s.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
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

// messageResource is the subset of a Twilio Message read from create/fetch.
type messageResource struct {
	SID          string `json:"sid"`
	Status       string `json:"status"`
	ErrorCode    *int   `json:"error_code"`
	ErrorMessage string `json:"error_message"`
}

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

// twilioErrorHint explains the most common silent-undelivered codes.
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

// confirmDelivery polls the message status until a terminal state or
// deliveryConfirmTimeout. Only a definite failure is an error: a message still
// in flight at the deadline, a cancelled ctx or a missing SID never block a
// working send.
func (s *SMS) confirmDelivery(ctx context.Context, created messageResource) error {
	if isDeliveryFailure(created.Status) {
		return deliveryFailureError(created)
	}
	if isDeliverySuccess(created.Status) || strings.TrimSpace(created.SID) == "" {
		return nil
	}
	deadline := time.Now().Add(deliveryConfirmTimeout)
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(s.pollInterval):
		}

		m, err := s.fetchMessage(ctx, created.SID)
		if err != nil {
			if time.Now().After(deadline) {
				return nil
			}
			continue
		}
		if isDeliveryFailure(m.Status) {
			return deliveryFailureError(m)
		}
		if isDeliverySuccess(m.Status) || time.Now().After(deadline) {
			return nil
		}
	}
}

func (s *SMS) fetchMessage(ctx context.Context, sid string) (messageResource, error) {
	var m messageResource
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, fmt.Sprintf(messageURLFormat, s.accountSID, strings.TrimSpace(sid)), nil)
	if err != nil {
		return m, err
	}
	req.SetBasicAuth(s.accountSID, s.authToken)
	resp, err := s.client.Do(req)
	if err != nil {
		return m, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return m, fmt.Errorf("twilio message fetch status %d", resp.StatusCode)
	}
	err = json.NewDecoder(resp.Body).Decode(&m)
	return m, err
}
