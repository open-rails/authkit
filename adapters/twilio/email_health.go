package twilio

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
)

const (
	sendGridAPI = "https://api.sendgrid.com/v3"
	// maxSenderPages bounds the verified-sender listing a check walks.
	maxSenderPages = 10
)

// errCantTell marks a sender listing that did not answer: the API key may
// lack read access to it.
var errCantTell = errors.New("sendgrid listing unavailable")

// CheckHealth verifies, without sending an email, that this sender can
// deliver: the API key is valid and has the mail.send scope, and FromEmail is
// on a valid authenticated domain or is a verified sender. A key that can't
// read its domains and senders can't tell the second part, which counts as
// healthy.
func (e *Email) CheckHealth(ctx context.Context) error {
	var key struct {
		Scopes []string `json:"scopes"`
	}
	if err := e.apiGet(ctx, sendGridAPI+"/scopes", &key); err != nil {
		return fmt.Errorf("sendgrid API key check failed: %w", err)
	}
	if !slices.Contains(key.Scopes, "mail.send") {
		return errors.New("sendgrid API key lacks the mail.send scope")
	}

	domainOK, domainErr := e.onAuthenticatedDomain(ctx)
	if domainOK {
		return nil
	}
	senderOK, senderErr := e.isVerifiedSender(ctx)
	if senderOK || domainErr != nil || errors.Is(senderErr, errCantTell) {
		return nil
	}
	if senderErr != nil {
		return senderErr
	}
	return fmt.Errorf("sendgrid sender %s is neither on an authenticated domain nor a verified sender", e.fromEmail)
}

// onAuthenticatedDomain reports whether FromEmail's domain is a valid
// authenticated domain. Sending from a subdomain needs that subdomain
// authenticated, so the match is exact.
func (e *Email) onAuthenticatedDomain(ctx context.Context) (bool, error) {
	_, domain, ok := strings.Cut(e.fromEmail, "@")
	if !ok || domain == "" {
		return false, errCantTell
	}
	var domains []struct {
		Domain string `json:"domain"`
		Valid  bool   `json:"valid"`
	}
	if err := e.apiGet(ctx, sendGridAPI+"/whitelabel/domains?"+url.Values{"domain": {domain}}.Encode(), &domains); err != nil {
		return false, errCantTell
	}
	for _, d := range domains {
		if d.Valid && strings.EqualFold(d.Domain, domain) {
			return true, nil
		}
	}
	return false, nil
}

// isVerifiedSender reports whether FromEmail is a verified single sender; a
// listed but unverified one is an error.
func (e *Email) isVerifiedSender(ctx context.Context) (bool, error) {
	lastSeen := 0
	for range maxSenderPages {
		q := url.Values{}
		if lastSeen > 0 {
			q.Set("lastSeenID", strconv.Itoa(lastSeen))
		}
		var page struct {
			Results []struct {
				ID        int    `json:"id"`
				FromEmail string `json:"from_email"`
				Verified  bool   `json:"verified"`
			} `json:"results"`
		}
		if err := e.apiGet(ctx, sendGridAPI+"/verified_senders?"+q.Encode(), &page); err != nil {
			return false, errCantTell
		}
		if len(page.Results) == 0 {
			return false, nil
		}
		for _, r := range page.Results {
			if !strings.EqualFold(r.FromEmail, e.fromEmail) {
				continue
			}
			if !r.Verified {
				return false, fmt.Errorf("sendgrid sender %s is not verified yet", e.fromEmail)
			}
			return true, nil
		}
		next := page.Results[len(page.Results)-1].ID
		if next <= lastSeen {
			return false, errCantTell
		}
		lastSeen = next
	}
	return false, errCantTell
}

// apiGet performs an authenticated GET and decodes a 2xx JSON body into out.
func (e *Email) apiGet(ctx context.Context, apiURL string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiURL, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+e.apiKey)
	resp, err := e.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		var body struct {
			Errors []struct {
				Message string `json:"message"`
			} `json:"errors"`
		}
		if json.NewDecoder(resp.Body).Decode(&body) == nil && len(body.Errors) > 0 && body.Errors[0].Message != "" {
			return fmt.Errorf("sendgrid API %d: %s", resp.StatusCode, body.Errors[0].Message)
		}
		return fmt.Errorf("sendgrid API status %d", resp.StatusCode)
	}
	return json.NewDecoder(resp.Body).Decode(out)
}
