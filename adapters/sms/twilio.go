package smstwilio

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	core "github.com/open-rails/authkit/core"
)

// Sender sends SMS messages via Twilio Messaging API.
type Sender struct {
	AccountSID          string
	AuthToken           string
	MessagingServiceSID string
	AppName             string
	Client              *http.Client

	VerificationLinkURL func(token string) string
	ResetLinkURL        func(token string) string
}

// New creates a Twilio Messaging sender.
func New(accountSID, authToken, messagingServiceSID, appName string) *Sender {
	return &Sender{
		AccountSID:          strings.TrimSpace(accountSID),
		AuthToken:           strings.TrimSpace(authToken),
		MessagingServiceSID: strings.TrimSpace(messagingServiceSID),
		AppName:             strings.TrimSpace(appName),
	}
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
	app := s.AppName
	if app == "" {
		app = "Auth"
	}

	parts := make([]string, 0, 2)
	if strings.TrimSpace(msg.Code) != "" {
		parts = append(parts, fmt.Sprintf("%s verification code: %s", app, strings.TrimSpace(msg.Code)))
	}
	if strings.TrimSpace(msg.LinkToken) != "" {
		linkOrToken := strings.TrimSpace(msg.LinkToken)
		if s.VerificationLinkURL != nil {
			if built := strings.TrimSpace(s.VerificationLinkURL(linkOrToken)); built != "" {
				linkOrToken = built
			}
		}
		parts = append(parts, "Verify: "+linkOrToken)
	}

	return s.sendMessage(ctx, phone, strings.Join(parts, "\n"))
}

func (s *Sender) SendPasswordResetLink(ctx context.Context, phone, token string) error {
	app := s.AppName
	if app == "" {
		app = "Auth"
	}
	linkOrToken := strings.TrimSpace(token)
	if s.ResetLinkURL != nil {
		if built := strings.TrimSpace(s.ResetLinkURL(linkOrToken)); built != "" {
			linkOrToken = built
		}
	}
	body := fmt.Sprintf("%s password reset: %s", app, linkOrToken)
	return s.sendMessage(ctx, phone, body)
}

func (s *Sender) SendLoginCode(ctx context.Context, phone, code string) error {
	app := s.AppName
	if app == "" {
		app = "Auth"
	}
	body := fmt.Sprintf("%s login code: %s", app, strings.TrimSpace(code))
	return s.sendMessage(ctx, phone, body)
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

	apiURL := fmt.Sprintf("https://api.twilio.com/2010-04-01/Accounts/%s/Messages.json", s.AccountSID)
	formData := url.Values{}
	formData.Set("To", strings.TrimSpace(to))
	formData.Set("Body", strings.TrimSpace(body))
	formData.Set("MessagingServiceSid", s.MessagingServiceSID)

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
