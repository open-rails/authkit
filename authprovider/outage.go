package authprovider

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"sync/atomic"
)

// ErrProviderUnavailable marks a failure caused by the provider being
// unreachable or answering 5xx/429, as opposed to rejecting the request.
var ErrProviderUnavailable = errors.New("provider_unavailable")

type outageKey struct{}

// outageTransport flags the request context's outage marker when a round trip
// fails in transport or the provider answers 5xx/429.
type outageTransport struct{ base http.RoundTripper }

func (t outageTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	resp, err := t.base.RoundTrip(req)
	if flag, _ := req.Context().Value(outageKey{}).(*atomic.Bool); flag != nil &&
		(err != nil || resp.StatusCode >= 500 || resp.StatusCode == http.StatusTooManyRequests) {
		flag.Store(true)
	}
	return resp, err
}

func withOutageTracking(c *http.Client) *http.Client {
	cp := *c
	if cp.Transport == nil {
		cp.Transport = http.DefaultTransport
	}
	cp.Transport = outageTransport{cp.Transport}
	return &cp
}

// trackOutage returns a context whose provider calls record outages, and a
// classifier that marks an error from those calls ErrProviderUnavailable when
// one occurred.
func trackOutage(ctx context.Context) (context.Context, func(error) error) {
	flag := new(atomic.Bool)
	return context.WithValue(ctx, outageKey{}, flag), func(err error) error {
		if err != nil && flag.Load() && !errors.Is(err, ErrProviderUnavailable) {
			return fmt.Errorf("%w: %w", ErrProviderUnavailable, err)
		}
		return err
	}
}
