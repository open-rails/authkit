package authcore

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestVerificationSendTimeout_DefaultAndConfigurable(t *testing.T) {
	if got := (&Service{}).verificationSendTimeout(); got != 15*time.Second {
		t.Fatalf("default timeout = %v, want 15s", got)
	}
	s := &Service{cfg: Config{Registration: RegistrationConfig{VerificationSendTimeout: 2 * time.Second}}}
	if got := s.verificationSendTimeout(); got != 2*time.Second {
		t.Fatalf("configured timeout = %v, want 2s", got)
	}
	// A nil Service must not panic and must fall back to the default.
	if got := (*Service)(nil).verificationSendTimeout(); got != 15*time.Second {
		t.Fatalf("nil-service timeout = %v, want 15s", got)
	}
}

// TestWithSendTimeout_BoundsBlockingSend simulates a configured-but-dead email/SMS
// provider whose send blocks: withSendTimeout must return promptly (around the
// timeout) with context.DeadlineExceeded instead of hanging the request.
func TestWithSendTimeout_BoundsBlockingSend(t *testing.T) {
	s := &Service{cfg: Config{Registration: RegistrationConfig{VerificationSendTimeout: 50 * time.Millisecond}}}
	start := time.Now()
	err := s.withSendTimeout(context.Background(), func(ctx context.Context) error {
		<-ctx.Done() // block until the bounded context cancels (dead provider)
		return ctx.Err()
	})
	elapsed := time.Since(start)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("err = %v, want context.DeadlineExceeded", err)
	}
	if elapsed > 2*time.Second {
		t.Fatalf("send took %v; expected to be bounded near the 50ms timeout (did NOT hang)", elapsed)
	}
}

// TestWithSendTimeout_PassThrough confirms a fast send is not disturbed: success
// stays nil and a provider error propagates unchanged (so callers can still map
// it to ErrEmailDeliveryFailed / ErrSMSDeliveryFailed).
func TestWithSendTimeout_PassThrough(t *testing.T) {
	s := &Service{cfg: Config{Registration: RegistrationConfig{VerificationSendTimeout: time.Second}}}
	if err := s.withSendTimeout(context.Background(), func(ctx context.Context) error { return nil }); err != nil {
		t.Fatalf("success send returned %v", err)
	}
	sentinel := errors.New("provider error")
	if err := s.withSendTimeout(context.Background(), func(ctx context.Context) error { return sentinel }); !errors.Is(err, sentinel) {
		t.Fatalf("err = %v, want sentinel provider error", err)
	}
}
