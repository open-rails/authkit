package twilio

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

const (
	twilioAPI    = "https://api.twilio.com/2010-04-01"
	messagingAPI = "https://messaging.twilio.com/v1"
	// maxListPages bounds the pages a check reads from one Twilio list.
	maxListPages = 20
)

// otherSenderKinds are the Messaging Service sender lists besides phone
// numbers, by path and JSON key.
var otherSenderKinds = []struct{ path, key string }{
	{"ShortCodes", "short_codes"},
	{"AlphaSenders", "alpha_senders"},
	{"DestinationAlphaSenders", "alpha_senders"},
	{"ChannelSenders", "senders"},
}

// CheckHealth reports, without sending an SMS, whether Twilio will refuse this
// sender. It fails when the credentials, account or Messaging Service are
// refused, the service has no sender, or every sender is a toll-free number
// without an approved verification (error 30032). A network error or 5xx on
// those lookups fails too; the next check re-arms. Anything else it can't
// tell counts as healthy. Refused toll-free senders beside working ones, and
// senders it can't tell about, log a warning on slog.Default, once per change.
func (s *SMS) CheckHealth(ctx context.Context) error {
	var account struct {
		Status string `json:"status"`
	}
	if err := s.apiGet(ctx, fmt.Sprintf("%s/Accounts/%s.json", twilioAPI, s.accountSID), &account); err != nil {
		return fmt.Errorf("twilio credential check failed: %w", err)
	}
	if st := strings.ToLower(strings.TrimSpace(account.Status)); st != "" && st != "active" {
		return fmt.Errorf("twilio account is not active (status=%s)", account.Status)
	}
	service := messagingAPI + "/Services/" + s.messagingServiceSID
	if err := s.apiGet(ctx, service, &struct{}{}); err != nil {
		return fmt.Errorf("messaging service check failed: %w", err)
	}
	pool, err := s.readSenderPool(ctx, service)
	if err != nil {
		return fmt.Errorf("messaging service sender check failed: %w", err)
	}

	if !pool.usable && len(pool.unknown) == 0 {
		s.refusedWarning.reset()
		s.unknownWarning.reset()
		if len(pool.refused) > 0 {
			return fmt.Errorf("every sender on messaging service %s is a toll-free number without an approved verification (%s); Twilio refuses them with error 30032",
				s.messagingServiceSID, strings.Join(pool.refused, ", "))
		}
		return fmt.Errorf("messaging service %s has no sender", s.messagingServiceSID)
	}
	s.refusedWarning.warn(ctx, strings.Join(pool.refused, ","),
		"authkit: Twilio refuses these toll-free SMS senders until their verification is approved (error 30032); SMS through them fails",
		"messaging_service", s.messagingServiceSID, "senders", pool.refused)
	s.unknownWarning.warn(ctx, strings.Join(pool.unknown, ","),
		"authkit: can't tell whether Twilio accepts these SMS senders; counting them as usable",
		"messaging_service", s.messagingServiceSID, "senders", pool.unknown)
	return nil
}

// senderPool is what a check learned about a Messaging Service's senders.
type senderPool struct {
	// usable is true once a sender Twilio isn't known to refuse is found.
	usable bool
	// refused are toll-free numbers without an approved verification.
	refused []string
	// unknown are numbers, or kinds of sender, the check can't tell about.
	unknown []string
}

type poolNumber struct {
	SID         string `json:"sid"`
	PhoneNumber string `json:"phone_number"`
}

// readSenderPool reads every phone number of the service at serviceURL and, when
// none is usable, the other kinds of sender until one has an entry. Only a
// network error or 5xx is an error; a list it can't read is unknown.
func (s *SMS) readSenderPool(ctx context.Context, serviceURL string) (senderPool, error) {
	var pool senderPool
	var numbers []poolNumber
	err := listEach(ctx, s, serviceURL+"/PhoneNumbers?PageSize=1000", "phone_numbers", func(n poolNumber) bool {
		numbers = append(numbers, n)
		return true
	})
	if err != nil {
		if transient(err) {
			return pool, err
		}
		pool.unknown = append(pool.unknown, "PhoneNumbers")
	}

	var tollFree []poolNumber
	for _, n := range numbers {
		if isTollFreeNumber(n.PhoneNumber) {
			tollFree = append(tollFree, n)
		} else {
			pool.usable = true
		}
	}
	if len(tollFree) > 0 {
		statuses, err := s.tollFreeStatuses(ctx)
		for _, n := range tollFree {
			switch {
			case err != nil:
				pool.unknown = append(pool.unknown, n.PhoneNumber)
			case anyApproved(statuses[n.SID], statuses[n.PhoneNumber]):
				pool.usable = true
			case allRefused(statuses[n.SID], statuses[n.PhoneNumber]):
				pool.refused = append(pool.refused, n.PhoneNumber)
			default:
				pool.unknown = append(pool.unknown, n.PhoneNumber)
			}
		}
	}

	for _, kind := range otherSenderKinds {
		if pool.usable {
			break
		}
		err := listEach(ctx, s, serviceURL+"/"+kind.path+"?PageSize=1", kind.key, func(json.RawMessage) bool {
			pool.usable = true
			return false
		})
		if err != nil {
			if transient(err) {
				return pool, err
			}
			pool.unknown = append(pool.unknown, kind.path)
		}
	}
	return pool, nil
}

// tollFreeStatuses lists the account's toll-free verification statuses, keyed
// by both the number's SID and the number.
func (s *SMS) tollFreeStatuses(ctx context.Context) (map[string][]string, error) {
	statuses := map[string][]string{}
	err := listEach(ctx, s, messagingAPI+"/Tollfree/Verifications?PageSize=1000", "verifications", func(v struct {
		SID    string `json:"tollfree_phone_number_sid"`
		Number string `json:"tollfree_phone_number"`
		Status string `json:"status"`
	}) bool {
		st := strings.ToUpper(strings.TrimSpace(v.Status))
		for _, k := range []string{strings.TrimSpace(v.SID), strings.TrimSpace(v.Number)} {
			if k != "" {
				statuses[k] = append(statuses[k], st)
			}
		}
		return true
	})
	return statuses, err
}

// anyApproved reports whether any verification is approved.
func anyApproved(statuses ...[]string) bool {
	for _, list := range statuses {
		for _, st := range list {
			if st == "TWILIO_APPROVED" {
				return true
			}
		}
	}
	return false
}

// allRefused reports whether Twilio surely refuses a toll-free number with
// these verifications: none, or each pending or rejected. Twilio blocks
// pending numbers too.
func allRefused(statuses ...[]string) bool {
	for _, list := range statuses {
		for _, st := range list {
			switch st {
			case "PENDING_REVIEW", "IN_REVIEW", "TWILIO_REJECTED":
			default:
				return false
			}
		}
	}
	return true
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

// listEach calls each for every item under key across the pages of the
// Messaging API list at apiURL, until each returns false. It follows
// meta.next_page_url only on the same origin.
func listEach[T any](ctx context.Context, s *SMS, apiURL, key string, each func(T) bool) error {
	for range maxListPages {
		var page map[string]json.RawMessage
		if err := s.apiGet(ctx, apiURL, &page); err != nil {
			return err
		}
		var items []T
		if raw, ok := page[key]; ok {
			if err := json.Unmarshal(raw, &items); err != nil {
				return fmt.Errorf("twilio list %s: %w", key, err)
			}
		}
		for _, item := range items {
			if !each(item) {
				return nil
			}
		}
		var meta struct {
			NextPageURL string `json:"next_page_url"`
		}
		if raw, ok := page["meta"]; ok {
			if err := json.Unmarshal(raw, &meta); err != nil {
				return fmt.Errorf("twilio list %s: %w", key, err)
			}
		}
		if meta.NextPageURL == "" {
			return nil
		}
		if !sameOrigin(apiURL, meta.NextPageURL) {
			return fmt.Errorf("twilio list %s: next page %q is on another host", key, meta.NextPageURL)
		}
		apiURL = meta.NextPageURL
	}
	return fmt.Errorf("twilio list %s: more than %d pages", key, maxListPages)
}

func sameOrigin(a, b string) bool {
	ua, errA := url.Parse(a)
	ub, errB := url.Parse(b)
	return errA == nil && errB == nil && ua.Scheme == ub.Scheme && ua.Host == ub.Host
}

// transient reports whether err is a network error or a 5xx: the lookup may
// pass on the next check.
func transient(err error) bool {
	var apiErr *twilioAPIError
	if errors.As(err, &apiErr) {
		return apiErr.status >= 500
	}
	var urlErr *url.Error
	return errors.As(err, &urlErr)
}

// twilioAPIError is a non-2xx Twilio API answer.
type twilioAPIError struct {
	status  int
	code    int
	message string
}

func (e *twilioAPIError) Error() string {
	if e.code != 0 || e.message != "" {
		return fmt.Sprintf("twilio API %d (code %d): %s", e.status, e.code, e.message)
	}
	return fmt.Sprintf("twilio API status %d", e.status)
}

// apiGet performs an authenticated GET and decodes a 2xx JSON body into out.
func (s *SMS) apiGet(ctx context.Context, apiURL string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiURL, nil)
	if err != nil {
		return err
	}
	req.SetBasicAuth(s.accountSID, s.authToken)
	resp, err := s.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		apiErr := &twilioAPIError{status: resp.StatusCode}
		var body struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		}
		if json.NewDecoder(resp.Body).Decode(&body) == nil {
			apiErr.code, apiErr.message = body.Code, strings.TrimSpace(body.Message)
		}
		return apiErr
	}
	return json.NewDecoder(resp.Body).Decode(out)
}
