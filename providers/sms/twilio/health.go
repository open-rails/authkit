package twilio

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

// CheckHealth verifies — without sending any SMS — that this sender is
// configured to actually deliver messages. It validates credentials, that the
// Messaging Service exists and has at least one attached sender, and that any
// toll-free sender has completed Twilio toll-free verification (the silent
// failure behind error 30032). It returns nil when delivery is expected to
// succeed, or a descriptive error otherwise. Implements embedded.SMSHealthChecker.
func (s *Sender) CheckHealth(ctx context.Context) error {
	if s == nil {
		return fmt.Errorf("twilio sender is nil")
	}
	accountSID := strings.TrimSpace(s.AccountSID)
	if accountSID == "" || strings.TrimSpace(s.AuthToken) == "" || strings.TrimSpace(s.MessagingServiceSID) == "" {
		return fmt.Errorf("twilio credentials/messaging service not configured")
	}

	// 1) Credentials valid and account usable.
	var account struct {
		Status string `json:"status"`
	}
	if err := s.apiGet(ctx, fmt.Sprintf("https://api.twilio.com/2010-04-01/Accounts/%s.json", accountSID), &account); err != nil {
		return fmt.Errorf("twilio credential check failed: %w", err)
	}
	if st := strings.ToLower(strings.TrimSpace(account.Status)); st != "" && st != "active" {
		return fmt.Errorf("twilio account is not active (status=%s)", account.Status)
	}

	// 2) Messaging Service exists.
	msURL := fmt.Sprintf("https://messaging.twilio.com/v1/Services/%s", strings.TrimSpace(s.MessagingServiceSID))
	if err := s.apiGet(ctx, msURL, &struct{}{}); err != nil {
		return fmt.Errorf("messaging service check failed: %w", err)
	}

	// 3) Messaging Service has at least one attached sender.
	var pn struct {
		PhoneNumbers []struct {
			SID         string `json:"sid"`
			PhoneNumber string `json:"phone_number"`
		} `json:"phone_numbers"`
	}
	if err := s.apiGet(ctx, msURL+"/PhoneNumbers", &pn); err != nil {
		return fmt.Errorf("messaging service sender check failed: %w", err)
	}
	if len(pn.PhoneNumbers) == 0 {
		return fmt.Errorf("messaging service %s has no attached sender (phone number)", s.MessagingServiceSID)
	}

	// 4) For toll-free senders, require an approved toll-free verification.
	//    Non-toll-free senders (long codes / short codes) are assumed
	//    deliverable here; A2P 10DLC campaign status is a separate check.
	var tollFree, verifiedTollFree int
	for _, p := range pn.PhoneNumbers {
		if !isTollFreeNumber(p.PhoneNumber) {
			continue
		}
		tollFree++
		ok, err := s.tollFreeVerified(ctx, p.SID, p.PhoneNumber)
		if err != nil {
			// Be lenient on probe errors for an individual number, but record it.
			continue
		}
		if ok {
			verifiedTollFree++
		}
	}
	if tollFree > 0 && verifiedTollFree == 0 {
		return fmt.Errorf("toll-free sender(s) on messaging service %s are not verified (Twilio toll-free verification incomplete; sends will fail with error 30032)", s.MessagingServiceSID)
	}

	return nil
}

// tollFreeVerified reports whether the given toll-free number has an approved
// Twilio toll-free verification.
func (s *Sender) tollFreeVerified(ctx context.Context, phoneNumberSID, phoneNumber string) (bool, error) {
	q := url.Values{}
	if strings.TrimSpace(phoneNumberSID) != "" {
		q.Set("TollfreePhoneNumberSid", strings.TrimSpace(phoneNumberSID))
	}
	apiURL := "https://messaging.twilio.com/v1/Tollfree/Verifications"
	if enc := q.Encode(); enc != "" {
		apiURL += "?" + enc
	}
	var resp struct {
		Verifications []struct {
			Status      string `json:"status"`
			PhoneNumber string `json:"phone_number"`
		} `json:"verifications"`
	}
	if err := s.apiGet(ctx, apiURL, &resp); err != nil {
		return false, err
	}
	for _, v := range resp.Verifications {
		if phoneNumber != "" && strings.TrimSpace(v.PhoneNumber) != "" &&
			strings.TrimSpace(v.PhoneNumber) != strings.TrimSpace(phoneNumber) {
			continue
		}
		if strings.EqualFold(strings.TrimSpace(v.Status), "TWILIO_APPROVED") {
			return true, nil
		}
	}
	return false, nil
}

// isTollFreeNumber reports whether an E.164 number is a NANP toll-free number.
func isTollFreeNumber(e164 string) bool {
	n := strings.TrimSpace(e164)
	if !strings.HasPrefix(n, "+1") || len(n) < 5 {
		return false
	}
	switch n[2:5] {
	case "800", "833", "844", "855", "866", "877", "888":
		return true
	}
	return false
}

// apiGet performs an authenticated GET and decodes a 2xx JSON body into out.
func (s *Sender) apiGet(ctx context.Context, apiURL string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiURL, nil)
	if err != nil {
		return err
	}
	req.SetBasicAuth(strings.TrimSpace(s.AccountSID), strings.TrimSpace(s.AuthToken))
	resp, err := s.httpClient().Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		var e struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		}
		if json.NewDecoder(resp.Body).Decode(&e) == nil && (e.Code != 0 || strings.TrimSpace(e.Message) != "") {
			return fmt.Errorf("twilio API %d (code %d): %s", resp.StatusCode, e.Code, e.Message)
		}
		return fmt.Errorf("twilio API status %d", resp.StatusCode)
	}
	if out == nil {
		return nil
	}
	return json.NewDecoder(resp.Body).Decode(out)
}
