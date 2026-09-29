package engine

// Durable account and group events (Deps.OnEvent) on the account lifecycle
// machinery. A change records its events in its own transaction: one
// account_events row per subscribed account issuer plus a River job in that
// issuer's fleet. A refused or rolled-back change records nothing; a committed
// one is delivered at least once. Delivery is ordered per subject (the user,
// else the application or group): a failing hook holds back that subject's
// later events and is retried with backoff, never exhausting.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/riverqueue/river"
	"github.com/riverqueue/river/riverdriver/riverpgxv5"

	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/db"
)

type accountEventArgs struct {
	Schema string `json:"schema"`
	Issuer string `json:"issuer"`
	Row    int64  `json:"row"`
}

func (accountEventArgs) Kind() string { return "authkit_account_event" }

func accountEventQueue(schema, issuer string) string {
	digest := sha256.Sum256([]byte(schema + "\x00" + issuer))
	return "authkit_events-" + hex.EncodeToString(digest[:20])
}

// maxEventRetryDelay caps the backoff of a failing hook.
const maxEventRetryDelay = time.Hour

// eventRetryDelay is the wait before attempt n+1 after n failures: 2s, 4s, …
// up to an hour.
func eventRetryDelay(failures int) time.Duration {
	return min(time.Second<<min(failures, 12), maxEventRetryDelay)
}

func userEvent(kind iam.EventKind, userID string) iam.Event {
	return iam.Event{Kind: kind, UserID: canonicalID(userID)}
}

// canonicalID is id in the form PostgreSQL returns, when it is a uuid.
func canonicalID(id string) string {
	if canonical, ok := canonicalUUID(id); ok {
		return canonical
	}
	return id
}

func groupEvent(kind iam.EventKind, groupID string, persona iam.Persona) iam.Event {
	return iam.Event{Kind: kind, GroupID: groupID, Persona: persona}
}

// roleEvent is subject's role in the group going from previous to current.
func roleEvent(groupID string, persona iam.Persona, subject iam.Subject, previous, current iam.Role) iam.Event {
	e := iam.Event{Kind: iam.EventRoleChanged, GroupID: groupID, Persona: persona, Previous: string(previous), Current: string(current)}
	switch {
	case previous == "":
		e.Kind = iam.EventRoleGranted
	case current == "":
		e.Kind = iam.EventRoleRevoked
	}
	if subject.Kind == iam.SubjectKindUser {
		e.UserID = canonicalID(subject.ID)
	} else {
		e.ApplicationID = canonicalID(subject.ID)
	}
	return e
}

// eventSubject is the ordering key of e.
func eventSubject(e iam.Event) string {
	switch {
	case e.UserID != "":
		return "user:" + e.UserID
	case e.ApplicationID != "":
		return "application:" + e.ApplicationID
	default:
		return "group:" + e.GroupID
	}
}

// accountIdentity is the evented part of an account row.
type accountIdentity struct{ email, phone, username string }

func readAccountIdentity(ctx context.Context, q db.DBTX, userID string) (accountIdentity, error) {
	var id accountIdentity
	err := q.QueryRow(ctx, `SELECT COALESCE(email::text,''), COALESCE(phone_number,''), COALESCE(username::text,'') FROM users WHERE id=$1::uuid`, userID).Scan(&id.email, &id.phone, &id.username)
	return id, err
}

// identityChanges reads the account again and returns the events of what
// changed since before.
func identityChanges(ctx context.Context, q db.DBTX, userID string, before accountIdentity) ([]iam.Event, error) {
	after, err := readAccountIdentity(ctx, q, userID)
	if err != nil {
		return nil, err
	}
	var out []iam.Event
	for _, f := range []struct {
		kind            iam.EventKind
		previous, value string
	}{
		{iam.EventUserEmailChanged, before.email, after.email},
		{iam.EventUserPhoneChanged, before.phone, after.phone},
		{iam.EventUserUsernameChanged, before.username, after.username},
	} {
		if f.previous != f.value {
			out = append(out, iam.Event{Kind: f.kind, UserID: userID, Previous: f.previous, Current: f.value})
		}
	}
	return out, nil
}

// emitEvents records events a made in q, the change's transaction, for every
// account issuer subscribed to events. The fleet rows stay share-locked until
// commit, so a fleet cannot be rebound under a pending event.
func (s *Engine) emitEvents(ctx context.Context, q db.DBTX, a iam.Actor, events ...iam.Event) error {
	if len(events) == 0 {
		return nil
	}
	tx, ok := q.(pgx.Tx)
	if !ok {
		return errors.New("authkit: events are recorded only in the transaction of their change")
	}
	type subscriber struct{ issuer, schema string }
	rows, err := tx.Query(ctx, `SELECT issuer, river_schema FROM account_delivery_fleets WHERE events AND issuer=ANY($1) ORDER BY issuer FOR KEY SHARE`, s.accountIssuers())
	if err != nil {
		return err
	}
	subscribers, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (subscriber, error) {
		var sub subscriber
		return sub, row.Scan(&sub.issuer, &sub.schema)
	})
	if err != nil || len(subscribers) == 0 {
		return err
	}
	actorKind, actorID := string(a.Kind()), a.ID()
	ids := make([]string, len(events))
	for i := range events {
		if ids[i], err = newUUIDV7String(); err != nil {
			return err
		}
	}
	for _, sub := range subscribers {
		client, err := s.eventRiver(sub.schema)
		if err != nil {
			return err
		}
		for i, e := range events {
			var row int64
			err := tx.QueryRow(ctx, `INSERT INTO account_events
 (issuer,subject,event_id,kind,actor_kind,actor_id,user_id,group_id,persona,application_id,previous_value,current_value,reason,until)
 VALUES ($1,$2,$3::uuid,$4,$5,$6,$7::uuid,$8::uuid,$9,$10::uuid,$11,$12,$13,$14) RETURNING id`,
				sub.issuer, eventSubject(e), ids[i], string(e.Kind), actorKind, actorID, nullable(e.UserID), nullable(e.GroupID), string(e.Persona), nullable(e.ApplicationID), e.Previous, e.Current, e.Reason, e.Until).Scan(&row)
			if err != nil {
				return fmt.Errorf("authkit: record %s event: %w", e.Kind, err)
			}
			if _, err := client.InsertTx(ctx, tx, accountEventArgs{Schema: s.dbSchema(), Issuer: sub.issuer, Row: row}, &river.InsertOpts{Queue: accountEventQueue(s.dbSchema(), sub.issuer)}); err != nil {
				return err
			}
		}
	}
	return nil
}

// eventRiver is a producer for the River fleet in schema: this runtime's
// client, else an insert-only client (no workers, polling or pool of its
// own) writing through the change's transaction.
func (s *Engine) eventRiver(schema string) (*river.Client[pgx.Tx], error) {
	if m := s.maintenance; m != nil {
		m.mu.Lock()
		local := m.client
		m.mu.Unlock()
		if local != nil && local.Schema() == schema {
			return local, nil
		}
	}
	if c, ok := s.eventProducers.Load(schema); ok {
		return c.(*river.Client[pgx.Tx]), nil
	}
	c, err := river.NewClient(riverpgxv5.New(s.pg), &river.Config{Schema: schema})
	if err != nil {
		return nil, err
	}
	actual, _ := s.eventProducers.LoadOrStore(schema, c)
	return actual.(*river.Client[pgx.Tx]), nil
}

type accountEventWorker struct {
	river.WorkerDefaults[accountEventArgs]
	engine *Engine
}

func (w *accountEventWorker) Work(ctx context.Context, job *river.Job[accountEventArgs]) error {
	if job.Args.Schema != w.engine.dbSchema() || job.Args.Issuer != w.engine.cfg.Token.Issuer {
		return river.JobCancel(errors.New("authkit: account event routed to a different application"))
	}
	err := w.engine.deliverEvent(ctx, job.Args.Row)
	var snooze *river.JobSnoozeError
	if err == nil || errors.As(err, &snooze) {
		return err
	}
	// Never exhaust River's attempts: the row stays pending until delivered.
	slog.ErrorContext(ctx, "authkit: account event delivery will retry", "row", job.Args.Row, "error", err)
	return river.JobSnooze(time.Minute)
}

// deliverEvent runs the hook for one recorded event, once every earlier event
// of its subject is delivered, and deletes the row. No transaction or pool
// connection is held while the hook runs.
func (s *Engine) deliverEvent(ctx context.Context, row int64) error {
	var e iam.Event
	var issuer, subject, kind, actorKind, persona string
	var userID, groupID, appID *string
	var failures int
	err := s.pg.QueryRow(ctx, `SELECT issuer, subject, event_id::text, kind, occurred_at, actor_kind, actor_id, user_id::text, group_id::text, persona,
 application_id::text, previous_value, current_value, reason, until, attempts FROM account_events WHERE id=$1`, row).Scan(
		&issuer, &subject, &e.ID, &kind, &e.OccurredAt, &actorKind, &e.ActorID, &userID, &groupID, &persona, &appID, &e.Previous, &e.Current, &e.Reason, &e.Until, &failures)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil // delivered
	}
	if err != nil {
		return err
	}
	if issuer != s.cfg.Token.Issuer {
		return river.JobCancel(errors.New("authkit: account event issuer mismatch"))
	}
	e.Kind, e.ActorKind, e.Persona = iam.EventKind(kind), iam.ActorKind(actorKind), iam.Persona(persona)
	e.UserID, e.GroupID, e.ApplicationID = deref(userID), deref(groupID), deref(appID)
	var blocked bool
	var wait float64
	err = s.pg.QueryRow(ctx, `SELECT count(*)>0, COALESCE(EXTRACT(EPOCH FROM max(retry_at)-statement_timestamp()),0)::float8
 FROM account_events WHERE issuer=$1 AND subject=$2 AND id<$3`, issuer, subject, row).Scan(&blocked, &wait)
	if err != nil {
		return err
	}
	if blocked {
		// Wake after the earliest failed predecessor's next attempt.
		return river.JobSnooze(time.Second + max(time.Duration(wait*float64(time.Second)), 0))
	}
	if s.onEvent != nil {
		if err := invokeEventHook(ctx, s.onEvent, e); err != nil {
			delay := eventRetryDelay(failures + 1)
			if _, uerr := s.pg.Exec(ctx, `UPDATE account_events SET attempts=attempts+1, retry_at=statement_timestamp()+make_interval(secs => $2) WHERE id=$1`, row, delay.Seconds()); uerr != nil {
				return errors.Join(err, uerr)
			}
			slog.WarnContext(ctx, "authkit: event hook failed; will retry", "event_id", e.ID, "kind", e.Kind, "attempt", failures+1, "retry_in", delay, "error", err)
			return river.JobSnooze(delay)
		}
	}
	_, err = s.pg.Exec(ctx, `DELETE FROM account_events WHERE id=$1`, row)
	return err
}

func invokeEventHook(ctx context.Context, hook func(context.Context, iam.Event) error, e iam.Event) (err error) {
	defer func() {
		if recovered := recover(); recovered != nil {
			err = fmt.Errorf("event hook panicked: %v", recovered)
		}
	}()
	return hook(ctx, e)
}
