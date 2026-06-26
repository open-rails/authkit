// Package clickhouse is AuthKit's first-party ClickHouse adapter for the
// session-event audit log. It implements both the session-event LOGGER (write)
// and READER (read, for admin sign-in / login-history views) against the bundled
// migrations/clickhouse schema (the user_auth_session_events table).
//
// Hosts opt in by importing this package and passing WithClickHouse(conn) to
// embedded.New. Keeping the constructor here (rather than on embedded) keeps the
// ClickHouse driver out of the dependency graph of embedders that don't use it.
package clickhouse

import (
	"context"
	"fmt"
	"strings"
	"time"

	chdriver "github.com/ClickHouse/clickhouse-go/v2/lib/driver"
	authcore "github.com/open-rails/authkit/internal/authcore"
)

// Adapter logs and reads AuthKit session-lifecycle events in ClickHouse. The conn
// must target a database migrated with migrations/clickhouse.
type Adapter struct {
	conn chdriver.Conn
}

// New builds a ClickHouse-backed auth-event logger+reader over conn.
func New(conn chdriver.Conn) *Adapter { return &Adapter{conn: conn} }

// The adapter satisfies both audit interfaces (one type backs writes and reads).
var (
	_ authcore.AuthEventLogger    = (*Adapter)(nil)
	_ authcore.AuthEventLogReader = (*Adapter)(nil)
)

// WithClickHouse wires a ClickHouse-backed adapter as AuthKit's session-event sink
// (the embedded client then also exposes it as the admin-history reader). Pass it
// to embedded.New: embedded.New(cfg, pg, clickhouse.WithClickHouse(conn)).
func WithClickHouse(conn chdriver.Conn) authcore.Option {
	return authcore.WithAuthLogger(New(conn))
}

const insertSessionEventSQL = `INSERT INTO user_auth_session_events
(occurred_at, issuer, user_id, session_id, event, method, reason, ip_addr, user_agent)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`

// LogSessionEvent appends one session-lifecycle event. Best-effort: the caller
// (authcore) already treats logging failures as non-fatal.
func (a *Adapter) LogSessionEvent(ctx context.Context, e authcore.AuthSessionEvent) error {
	occurred := e.OccurredAt
	if occurred.IsZero() {
		occurred = time.Now().UTC()
	}
	return a.conn.Exec(ctx, insertSessionEventSQL,
		occurred, e.Issuer, e.UserID, e.SessionID, string(e.Event),
		e.Method, e.Reason, e.IPAddr, e.UserAgent)
}

const selectSessionEventsSQL = `SELECT occurred_at, issuer, user_id, session_id, event, method, reason, ip_addr, user_agent
FROM user_auth_session_events`

// ListSessionEvents returns events for userID (all users when empty), filtered to
// the given event types (all types when none given), most recent first.
func (a *Adapter) ListSessionEvents(ctx context.Context, userID string, eventTypes ...authcore.SessionEventType) ([]authcore.AuthSessionEvent, error) {
	q := selectSessionEventsSQL + " WHERE 1=1"
	var args []any
	if userID != "" {
		q += " AND user_id = ?"
		args = append(args, userID)
	}
	if len(eventTypes) > 0 {
		ph := make([]string, len(eventTypes))
		for i, t := range eventTypes {
			ph[i] = "?"
			args = append(args, string(t))
		}
		q += " AND event IN (" + strings.Join(ph, ",") + ")"
	}
	q += " ORDER BY occurred_at DESC"

	rows, err := a.conn.Query(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("clickhouse: list session events: %w", err)
	}
	defer rows.Close()

	var out []authcore.AuthSessionEvent
	for rows.Next() {
		var (
			e     authcore.AuthSessionEvent
			event string
		)
		if err := rows.Scan(&e.OccurredAt, &e.Issuer, &e.UserID, &e.SessionID, &event, &e.Method, &e.Reason, &e.IPAddr, &e.UserAgent); err != nil {
			return nil, fmt.Errorf("clickhouse: scan session event: %w", err)
		}
		e.Event = authcore.SessionEventType(event)
		out = append(out, e)
	}
	return out, rows.Err()
}
