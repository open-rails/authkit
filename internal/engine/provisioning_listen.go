package engine

import (
	"context"
	"encoding/json"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5"
)

// provisioningChannel is where the users triggers say they recorded a change
// (migration 0029).
const provisioningChannel = "authkit_provisioning"

// listenProvisioning queues a target's run when the users triggers record a
// change for it, and every target's on each (re)connect, which catches up a
// change made while it was disconnected. It runs from Start until Close.
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
		slog.WarnContext(ctx, "authkit: provisioning listener interrupted; reconnecting", "error", err, "retry_in", wait)
		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		}
		wait = min(2*wait, time.Minute)
	}
}

// listenProvisioningOnce listens on a connection of its own, not the pool's,
// until it fails; listened reports that it got as far as listening.
func (s *Engine) listenProvisioningOnce(ctx context.Context) (listened bool, err error) {
	conn, err := pgx.ConnectConfig(ctx, s.pg.Config().ConnConfig.Copy())
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
	// Read after LISTEN, so no change is missed between the two.
	for _, t := range s.provisioning {
		if err := s.wakeProvisioning(ctx, t); err != nil {
			return true, err
		}
	}
	for {
		n, err := conn.WaitForNotification(ctx)
		if err != nil {
			return true, err
		}
		var change struct{ Schema, Issuer, Target string }
		if json.Unmarshal([]byte(n.Payload), &change) != nil || change.Schema != s.dbSchema() || change.Issuer != s.cfg.Token.Issuer {
			continue
		}
		if t := s.provisioningTarget(change.Target); t != nil {
			if err := s.wakeProvisioning(ctx, t); err != nil {
				return true, err
			}
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
		return scheduleDue(ctx, tx, s.maintenance.producer, s.provisioningArgs(t), *next)
	})
}
