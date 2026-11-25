package engine

// The text-message policy (#449, SMSConfig): every message goes only to an
// allowed region and a number that can be a person's phone, and passes the
// send limits against SMS pumping: per number, account, client address,
// destination country, number range and requesting client. A code message
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

// refusedNumberTypes are the number types never texted: revenue-share and
// service ranges SMS pumping uses, none of them a person's own phone.
var refusedNumberTypes = map[phonenumbers.PhoneNumberType]string{
	phonenumbers.PREMIUM_RATE:    "premium_rate",
	phonenumbers.SHARED_COST:     "shared_cost",
	phonenumbers.UAN:             "uan",
	phonenumbers.VOICEMAIL:       "voicemail",
	phonenumbers.PAGER:           "pager",
	phonenumbers.PERSONAL_NUMBER: "personal_number",
	phonenumbers.TOLL_FREE:       "toll_free",
}

// smsRegion is number's region, refused unless SMS.AllowedCountries admits
// it (phone_country_not_allowed) and its type can be a person's phone
// (phone_number_not_allowed): both before anything is looked up or sent.
func (s *Engine) smsRegion(number string) (string, error) {
	n, err := phonenumbers.Parse(number, "")
	region := ""
	if err == nil {
		if region = phonenumbers.GetRegionCodeForNumber(n); region == phonenumbers.UNKNOWN_REGION {
			region = ""
		}
	}
	if allowed := s.cfg.SMS.AllowedCountries; len(allowed) > 0 && !slices.Contains(allowed, region) {
		return region, errmodel.E(errmodel.CodePhoneCountryNotAllowed, errmodel.WithDetails(errmodel.PhoneCountry{Country: region}))
	}
	if err == nil {
		if reason, refused := refusedNumberTypes[phonenumbers.GetNumberType(n)]; refused {
			return region, iam.RefuseSMSDestination(reason)
		}
	}
	return region, nil
}

// smsRange is number's block of 10,000 consecutive numbers: the number
// without its last four digits.
func smsRange(number string) string {
	if len(number) < 9 {
		return ""
	}
	return number[:len(number)-4]
}

// smsSpend is a text's spend of the budgets that count unconfirmed texts
// (sms_range, sms_client): the code it carried, once proven, gives it back.
type smsSpend struct {
	Bucket string `json:"bucket"`
	Key    string `json:"key"`
	Entry  string `json:"entry"`
}

type smsReceiptKey struct{}

// withSMSReceipt asks sendSMS to record its refundable spends in the
// returned slice, for a code flow to keep beside its challenge.
func withSMSReceipt(ctx context.Context) (context.Context, *[]smsSpend) {
	receipt := &[]smsSpend{}
	return context.WithValue(ctx, smsReceiptKey{}, receipt), receipt
}

// refundSMS gives back spends whose code was proven: a number that converts
// is no sign of pumping.
func (s *Engine) refundSMS(ctx context.Context, spends []smsSpend) {
	if s.sendLimiter == nil {
		return
	}
	for _, sp := range spends {
		s.sendLimiter.Refund(ctx, sp.Bucket, sp.Key, ratelimit.Result{Allowed: true, Entry: sp.Entry})
	}
}

// admitSMS spends one message of each send limit msg falls under; the first
// spent is rate_limited, and one per number or account is quotaSpent too. A
// code proving a number someone typed also spends the range and client
// budgets, into ctx's receipt; other texts go to numbers an account proved.
func (s *Engine) admitSMS(ctx context.Context, msg iam.SMSMessage, region string) error {
	// A notice to a number the account just replaced is the owner's alarm,
	// never withheld.
	if s.sendLimiter == nil || msg.Kind == iam.MessageContactChanged {
		return nil
	}
	var spent []smsSpend
	refund := func() {
		for _, sp := range spent {
			s.sendLimiter.Refund(ctx, sp.Bucket, sp.Key, ratelimit.Result{Allowed: true, Entry: sp.Entry})
		}
	}
	limits := []struct{ bucket, key string }{
		{httpapi.RLSMSNumber, msg.To},
		{httpapi.RLSMSAccount, msg.UserID},
		{httpapi.RLSMSAddress, authflow.ClientAddressFrom(ctx)},
		{httpapi.RLSMSCountry, region},
	}
	if msg.Kind == iam.MessageVerification {
		limits = append(limits,
			struct{ bucket, key string }{httpapi.RLSMSRange, smsRange(msg.To)},
			struct{ bucket, key string }{httpapi.RLSMSClient, authflow.RequestClientFrom(ctx)})
	}
	for _, l := range limits {
		if l.key == "" {
			continue
		}
		key := l.bucket + ":" + l.key
		res := s.sendLimiter.Allow(ctx, l.bucket, key)
		if !res.Allowed {
			// A refused text spends no budget that counts unconfirmed ones.
			refund()
			err := httpapi.RateLimitError(l.bucket, res)
			if l.bucket == httpapi.RLSMSNumber || l.bucket == httpapi.RLSMSAccount {
				return quotaSpent{err}
			}
			return err
		}
		if l.bucket == httpapi.RLSMSRange || l.bucket == httpapi.RLSMSClient {
			spent = append(spent, smsSpend{Bucket: l.bucket, Key: key, Entry: res.Entry})
		}
	}
	if receipt, ok := ctx.Value(smsReceiptKey{}).(*[]smsSpend); ok {
		*receipt = append(*receipt, spent...)
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
