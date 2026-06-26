package authcore

import (
	"context"
	"database/sql"
	"strings"
	"time"

	"github.com/ClickHouse/clickhouse-go/v2"
)

type clickHouseAuthLog struct {
	conn clickhouse.Conn
}

func newClickHouseAuthLog(conn clickhouse.Conn) *clickHouseAuthLog {
	if conn == nil {
		return nil
	}
	return &clickHouseAuthLog{conn: conn}
}

func (l *clickHouseAuthLog) LogSessionEvent(ctx context.Context, e AuthSessionEvent) error {
	if l == nil || l.conn == nil {
		return nil
	}
	occurredAt := e.OccurredAt.UTC()
	if occurredAt.IsZero() {
		occurredAt = time.Now().UTC()
	}
	return l.conn.Exec(ctx, `
		INSERT INTO user_auth_session_events
			(occurred_at, issuer, user_id, session_id, event, method, reason, ip_addr, user_agent)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
	`, occurredAt, e.Issuer, e.UserID, e.SessionID, string(e.Event), nullableString(e.Method), nullableString(e.Reason), nullableString(e.IPAddr), nullableString(e.UserAgent))
}

func (l *clickHouseAuthLog) ListSessionEvents(ctx context.Context, userID string, eventTypes ...SessionEventType) ([]AuthSessionEvent, error) {
	if l == nil || l.conn == nil {
		return nil, nil
	}
	query := `
		SELECT occurred_at, issuer, user_id, session_id, event, method, reason, ip_addr, user_agent
		  FROM user_auth_session_events
		 WHERE 1 = 1`
	args := []any{}
	if userID = strings.TrimSpace(userID); userID != "" {
		query += " AND user_id = ?"
		args = append(args, userID)
	}
	if len(eventTypes) > 0 {
		events := make([]string, 0, len(eventTypes))
		for _, eventType := range eventTypes {
			if eventType != "" {
				events = append(events, string(eventType))
			}
		}
		if len(events) > 0 {
			query += " AND event IN ?"
			args = append(args, events)
		}
	}
	query += " ORDER BY occurred_at DESC LIMIT 500"

	rows, err := l.conn.Query(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []AuthSessionEvent
	for rows.Next() {
		var e AuthSessionEvent
		var event string
		var method, reason, ip, ua sql.NullString
		if err := rows.Scan(&e.OccurredAt, &e.Issuer, &e.UserID, &e.SessionID, &event, &method, &reason, &ip, &ua); err != nil {
			return nil, err
		}
		e.Event = SessionEventType(event)
		e.Method = stringPtrFromNull(method)
		e.Reason = stringPtrFromNull(reason)
		e.IPAddr = stringPtrFromNull(ip)
		e.UserAgent = stringPtrFromNull(ua)
		out = append(out, e)
	}
	return out, rows.Err()
}

func nullableString(p *string) any {
	if p == nil {
		return nil
	}
	return *p
}

func stringPtrFromNull(s sql.NullString) *string {
	if !s.Valid {
		return nil
	}
	return &s.String
}
