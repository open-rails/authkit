package engine

import (
	"context"
	"encoding/json"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/open-rails/authkit/internal/config"
)

// provisioningChannel is where the users triggers say they recorded a change
// (migration 0029).
const provisioningChannel = "authkit_provisioning"

// listenProvisioning queues a target's run when the users triggers record a
// change for it. The provisioning_changes rows are the truth and a
// notification only a wake-up: every target is woken on each (re)connect and
// every Tuning.ListenerCheck, which catches up a change whose notification was
// lost. It runs from Start until Close.
func (s *Engine) listenProvisioning(ctx context.Context) {
	wait := time.Second
	for {
		listened, err := s.listenProvisioningOnce(ctx)
		if ctx.Err() != nil {
			return
		}
		if listened {
			wait = time.Second
		}
		s.log.WarnContext(ctx, "authkit: provisioning listener interrupted; reconnecting", "error", err, "retry_in", wait)
		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		}
		wait = min(2*wait, time.Minute)
	}
}

// listenerPing bounds the round trip that proves the listener's connection
// alive at each check.
const listenerPing = 5 * time.Second

// listenProvisioningOnce listens on a session of its own (dialSession) until
// it fails; listened reports that it got as far as listening.
func (s *Engine) listenProvisioningOnce(ctx context.Context) (listened bool, err error) {
	conn, err := s.dialSession(ctx)
	if err != nil {
		return false, err
	}
	defer func() {
		closing, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = conn.Close(closing)
	}()
	if _, err := conn.Exec(ctx, "LISTEN "+provisioningChannel); err != nil {
		return false, err
	}
	every := config.Tuned(s.cfg).ListenerCheck
	for {
		// Read after LISTEN, so no change is missed between the two.
		for _, t := range s.provisioning {
			if err := s.wakeProvisioning(ctx, t); err != nil {
				return true, err
			}
		}
		check := time.Now().Add(every)
		for {
			wait, cancel := context.WithDeadline(ctx, check)
			n, err := conn.WaitForNotification(wait)
			cancel()
			if ctx.Err() != nil {
				return true, ctx.Err()
			}
			if err != nil {
				if !time.Now().Before(check) {
					break
				}
				return true, err
			}
			var change struct{ Schema, Issuer, Target string }
			if json.Unmarshal([]byte(n.Payload), &change) != nil || change.Schema != s.dbSchema() || change.Issuer != s.cfg.Issuer {
				continue
			}
			if t := s.provisioningTarget(change.Target); t != nil {
				if err := s.wakeProvisioning(ctx, t); err != nil {
					return true, err
				}
			}
		}
		// A LISTEN already held changes nothing: the round trip is the ping.
		ping, cancel := context.WithTimeout(ctx, listenerPing)
		_, err := conn.Exec(ping, "LISTEN "+provisioningChannel)
		cancel()
		if err != nil {
			return true, err
		}
	}
}

// wakeProvisioning schedules t's run at its next due instant.
func (s *Engine) wakeProvisioning(ctx context.Context, t *provisioningTarget) error {
	if t.invalid != nil {
		return nil
	}
	next, err := s.provisioningNextRun(ctx, t)
	if err != nil || next == nil {
		return err
	}
	return pgx.BeginFunc(ctx, s.pg, func(tx pgx.Tx) error {
		return s.scheduleDue(ctx, tx, s.maintenance.producer, s.provisioningArgs(t), *next)
	})
}
