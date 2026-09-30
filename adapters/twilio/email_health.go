package twilio

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
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

// CheckHealth reports, without sending an email, whether SendGrid will refuse
// this sender: it fails only when the API key is rejected (401) or lacks the
// mail.send scope, and anything it can't tell counts as healthy. SendGrid
// enforces sender identity only on some accounts, so a FromEmail on no valid
// authenticated domain and no verified sender only logs a warning on
// slog.Default, once per change.
func (e *Email) CheckHealth(ctx context.Context) error {
	var key struct {
		Scopes []string `json:"scopes"`
	}
	if err := e.apiGet(ctx, sendGridAPI+"/scopes", &key); err != nil {
		var apiErr *apiError
		if errors.As(err, &apiErr) && apiErr.status == http.StatusUnauthorized {
			return fmt.Errorf("sendgrid API key rejected: %w", err)
		}
		return nil
	}
	if !slices.Contains(key.Scopes, "mail.send") {
		return errors.New("sendgrid API key lacks the mail.send scope")
	}
	if problem, ok := e.senderIdentity(ctx); ok {
		e.recordSenderProblem(ctx, problem)
	}
	return nil
}

// recordSenderProblem keeps the latest sender-identity verdict and warns when
// it becomes a new problem.
func (e *Email) recordSenderProblem(ctx context.Context, problem string) {
	e.senderMu.Lock()
	changed := problem != e.senderProblem
	e.senderProblem = problem
	e.senderMu.Unlock()
	if changed && problem != "" {
		slog.WarnContext(ctx, "authkit: SendGrid sender is unauthenticated; deliverability may suffer",
			"from", e.fromEmail, "reason", problem)
	}
}

// senderIdentity names what leaves FromEmail unauthenticated, "" when it is on
// a valid authenticated domain or is a verified sender. ok is false when the
// key can't read its domains or senders.
func (e *Email) senderIdentity(ctx context.Context) (problem string, ok bool) {
	onDomain, err := e.onAuthenticatedDomain(ctx)
	if err != nil {
		return "", false
	}
	if onDomain {
		return "", true
	}
	listed, verified, err := e.singleSender(ctx)
	switch {
	case err != nil:
		return "", false
	case verified:
		return "", true
	case listed:
		return "single sender not verified yet", true
	}
	return "no valid authenticated domain and no verified single sender", true
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

// singleSender reports whether FromEmail is listed as a single sender and
// whether that sender is verified.
func (e *Email) singleSender(ctx context.Context) (listed, verified bool, err error) {
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
			return false, false, errCantTell
		}
		if len(page.Results) == 0 {
			return false, false, nil
		}
		for _, r := range page.Results {
			if strings.EqualFold(r.FromEmail, e.fromEmail) {
				return true, r.Verified, nil
			}
		}
		next := page.Results[len(page.Results)-1].ID
		if next <= lastSeen {
			return false, false, errCantTell
		}
		lastSeen = next
	}
	return false, false, errCantTell
}

// apiError is a non-2xx SendGrid API answer.
type apiError struct {
	status  int
	message string
}

func (e *apiError) Error() string {
	if e.message != "" {
		return fmt.Sprintf("sendgrid API %d: %s", e.status, e.message)
	}
	return fmt.Sprintf("sendgrid API status %d", e.status)
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
		apiErr := &apiError{status: resp.StatusCode}
		var body struct {
			Errors []struct {
				Message string `json:"message"`
			} `json:"errors"`
		}
		if json.NewDecoder(resp.Body).Decode(&body) == nil && len(body.Errors) > 0 {
			apiErr.message = body.Errors[0].Message
		}
		return apiErr
	}
	return json.NewDecoder(resp.Body).Decode(out)
}
