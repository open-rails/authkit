package engine

// The text-message policy (#449, SMSConfig): every message goes only to an
// allowed region and passes the send limits (per number, account, client
// address and destination country) against SMS pumping, and a code message
// names the origin its code is entered on.

import (
	"context"
	"net/url"
	"slices"
	"strings"

	"github.com/nyaruka/phonenumbers"

	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/authflow"
	"github.com/open-rails/authkit/internal/errmodel"
	"github.com/open-rails/authkit/internal/httpapi"
	"github.com/open-rails/authkit/internal/ratelimit"
)

// SetSMSLimiter spends text messages' send limits in rl, the HTTP surface's
// limiter (Deps.Redis, else memory). A headless Client sends only for its
// host and applies none.
func (s *Engine) SetSMSLimiter(rl ratelimit.Limiter) { s.smsLimiter = rl }

// phoneRegion is the ISO 3166-1 alpha-2 region of an E.164 number, "" when
// it has none.
func phoneRegion(number string) string {
	n, err := phonenumbers.Parse(number, "")
	if err != nil {
		return ""
	}
	region := phonenumbers.GetRegionCodeForNumber(n)
	if region == phonenumbers.UNKNOWN_REGION {
		return ""
	}
	return region
}

// smsRegion is number's region, refused unless SMS.AllowedCountries admits
// it: phone_country_not_allowed.
func (s *Engine) smsRegion(number string) (string, error) {
	region := phoneRegion(number)
	if allowed := s.cfg.SMS.AllowedCountries; len(allowed) > 0 && !slices.Contains(allowed, region) {
		return region, errmodel.E(errmodel.CodePhoneCountryNotAllowed, errmodel.WithDetails(errmodel.PhoneCountry{Country: region}))
	}
	return region, nil
}

// admitSMS spends one message of each send limit msg falls under; the first
// spent is rate_limited.
func (s *Engine) admitSMS(ctx context.Context, msg iam.SMSMessage, region string) error {
	// A notice to a number the account just replaced is the owner's alarm,
	// never withheld.
	if s.smsLimiter == nil || msg.Kind == iam.MessageContactChanged {
		return nil
	}
	for _, l := range []struct{ bucket, key string }{
		{httpapi.RLSMSNumber, msg.To},
		{httpapi.RLSMSAccount, msg.UserID},
		{httpapi.RLSMSAddress, authflow.ClientAddressFrom(ctx)},
		{httpapi.RLSMSCountry, region},
	} {
		if l.key == "" {
			continue
		}
		if res := s.smsLimiter.Allow(ctx, l.bucket, l.bucket+":"+l.key); !res.Allowed {
			return httpapi.RateLimitError(l.bucket, res)
		}
	}
	return nil
}

// codeDomain is the host codes are entered on: Frontend.BaseURL's.
func (s *Engine) codeDomain() string {
	u, err := url.Parse(s.cfg.Frontend.BaseURL)
	if err != nil {
		return ""
	}
	return strings.ToLower(u.Hostname())
}
