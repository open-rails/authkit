package auth

import (
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// Refusal is how a consumer answers a request it refuses for an error from
// Authenticate, Can or CheckRecentSignIn, or for ErrForbidden of its own (Can
// answered false, a capability is missing): the same status and challenge in
// every consumer, beside the consumer's own body.
type Refusal struct {
	// Status is 401, 403 or 503.
	Status int
	// Header is set on the response: a 401's WWW-Authenticate challenge and
	// the provider's own headers.
	Header http.Header
	// Metadata is the provider's Challenge.Metadata, for the body.
	Metadata map[string]any
}

// Refuse is the Refusal for err on r:
//   - ErrUnavailable, or an error matching none below (nil too): 503, the
//     check could not run.
//   - ErrStepUpRequired: 401, error="insufficient_user_authentication" with
//     the Challenge's max_age in seconds (RFC 9470).
//   - ErrUnauthenticated, ErrExpired, ErrRevoked or ErrSenderProofRequired:
//     401. The challenge names no error when r has no Authorization header,
//     else error="invalid_token", or "invalid_dpop_proof" for a sender proof
//     (RFC 6750 §3, RFC 9449 §7.1).
//   - ErrForbidden: 403.
//
// A challenge uses r's scheme: DPoP for a DPoP-bound request, else Bearer. A
// Challenge's Header is set last.
func Refuse(r *http.Request, err error) Refusal {
	out := Refusal{Status: http.StatusServiceUnavailable, Header: http.Header{}}
	var c *Challenge
	if errors.As(err, &c) {
		out.Metadata = c.Metadata
	}
	scheme, presented := "Bearer", false
	if r != nil {
		if fields := strings.Fields(r.Header.Get("Authorization")); len(fields) > 0 {
			presented = true
			if strings.EqualFold(fields[0], "DPoP") {
				scheme = "DPoP"
			}
		}
	}
	switch {
	case err == nil, errors.Is(err, ErrUnavailable):
	case errors.Is(err, ErrStepUpRequired):
		out.Status = http.StatusUnauthorized
		challenge := scheme + ` error="insufficient_user_authentication"`
		if c != nil && c.MaxAge > 0 {
			challenge += `, max_age="` + strconv.FormatInt(int64((c.MaxAge+time.Second-1)/time.Second), 10) + `"`
		}
		out.Header.Set("WWW-Authenticate", challenge)
	case errors.Is(err, ErrSenderProofRequired):
		out.Status = http.StatusUnauthorized
		out.Header.Set("WWW-Authenticate", `DPoP error="invalid_dpop_proof"`)
	case errors.Is(err, ErrUnauthenticated), errors.Is(err, ErrExpired), errors.Is(err, ErrRevoked):
		out.Status = http.StatusUnauthorized
		if presented {
			out.Header.Set("WWW-Authenticate", scheme+` error="invalid_token"`)
		} else {
			out.Header.Set("WWW-Authenticate", scheme)
		}
	case errors.Is(err, ErrForbidden):
		out.Status = http.StatusForbidden
	}
	if c != nil {
		for name, values := range c.Header {
			out.Header[http.CanonicalHeaderKey(name)] = append([]string(nil), values...)
		}
	}
	return out
}
