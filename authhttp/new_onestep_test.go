package authhttp

import (
	"testing"

	"github.com/open-rails/authkit/embedded"
	"github.com/stretchr/testify/require"
)

// #211: the one-step New builds engine + transport (engine deps via WithEngine)
// and returns the client; NewServer rejects WithEngine so the two-step path
// can't silently drop engine options.
func TestNewOneStep(t *testing.T) {
	pool := newNoDBPool(t)
	sender := &captureEmailSender{}

	svc, client, err := New(newServerTestConfig(), pool, WithEngine(embedded.WithEmailSender(sender)), WithoutRateLimiter())
	require.NoError(t, err)
	require.NotNil(t, svc)
	require.NotNil(t, client)
	require.Same(t, embedded.Unwrap(client), svc.svc, "transport must wrap the returned client's engine")

	// Two-step path: WithEngine is a loud construction error, not a silent no-op.
	twoStep := newServerClient(t, newServerTestConfig(), newNoDBPool(t))
	_, err = NewServer(twoStep, WithEngine(embedded.WithEmailSender(sender)))
	require.ErrorContains(t, err, "WithEngine is only valid with authhttp.New")
}
