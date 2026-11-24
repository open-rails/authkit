package engine

import (
	"context"
	"errors"
	"strings"

	"github.com/open-rails/authkit/internal/ratelimit"
	"github.com/open-rails/authkit/internal/secret"
)

// A code typed before the caller has proven anything (a code sign-in, a
// sign-up, proving or changing an address) belongs to the start that sent it.
// The start answers a random handle, and a confirm's code is checked only
// against the challenge it names. Wrong codes count per challenge and
// maxChallengeFailures burn it; starts never replace each other. A link keeps
// its own token, which finds the challenge it was sent with.
const maxChallengeFailures = 5

// newChallengeHandle is a challenge's 128-bit handle.
func newChallengeHandle() string { return secret.Token(16) }

// SetSendLimiter spends send quotas in rl, the HTTP surface's limiter
// (Deps.Redis, else memory). A headless Client sends only for its host and
// applies none.
func (s *Engine) SetSendLimiter(rl ratelimit.Limiter) { s.sendLimiter = rl }

// admitCode spends one send of destination's quota in bucket. A start past it
// sends and stores nothing and answers as if it had, so nobody can spend
// another account's starts into a refusal.
func (s *Engine) admitCode(ctx context.Context, bucket, destination string) bool {
	destination = strings.ToLower(strings.TrimSpace(destination))
	if s.sendLimiter == nil || destination == "" {
		return true
	}
	id := secret.Hash(destination)
	key := bucket + ":id:" + id
	if tenant, err := s.tenantID(ctx); err == nil {
		key = bucket + ":tenant:" + tenant.String() + ":id:" + id
	}
	return s.sendLimiter.Allow(ctx, bucket, key).Allowed
}

// quotaSpent is a send refused by a quota per destination or account. A
// challenge's start answers it as sent; any other send is rate_limited.
type quotaSpent struct{ error }

func (q quotaSpent) Unwrap() error { return q.error }

func withheld(err error) bool {
	var q quotaSpent
	return errors.As(err, &q)
}
