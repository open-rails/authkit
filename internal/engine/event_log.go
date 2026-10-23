package engine

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/cursor"
	"github.com/open-rails/authkit/internal/db"
	"github.com/open-rails/authkit/internal/errmodel"
	"github.com/open-rails/helpers/eventlog"
	eventpg "github.com/open-rails/helpers/eventlog/postgres"
)

type eventLogCursor struct {
	Version  int      `json:"v"`
	Epoch    string   `json:"e"`
	Scope    string   `json:"s"`
	Kinds    []string `json:"k"`
	Position int64    `json:"p"`
	EventID  string   `json:"i"`
}

func eventLogScope(tenant iam.TenantID) string {
	if tenant.IsZero() {
		return "authority"
	}
	return tenant.String()
}

// appendEventLog queues immutable facts in the mutation transaction. Shared
// deferred flush locks all touched scopes in order and allocates positions only
// at commit, including when a transaction appends in several calls.
func (s *Engine) appendEventLog(ctx context.Context, tx pgx.Tx, events []iam.Event) error {
	for _, e := range events {
		if e.Kind == "" {
			e.Kind = e.Type
		}
		payload, err := json.Marshal(e)
		if err != nil {
			return err
		}
		store, err := eventpg.New(s.pg, eventpg.Config{Schema: s.dbSchema(), Source: "authkit", Scope: eventLogScope(e.TenantID)})
		if err != nil {
			return err
		}
		if err = store.AppendTx(ctx, tx, eventlog.Event{ID: e.ID, Source: "authkit", Type: string(e.Kind), Version: e.Version, OccurredAt: e.OccurredAt, Subject: eventlog.Subject{Type: string(e.SubjectKind), ID: e.SubjectID}, Data: payload}); err != nil {
			return err
		}
	}
	return nil
}

// ListEvents reads one authorized scope using shared paging and the historical
// AuthKit cursor codec. Product authorization remains outside shared storage.
func (s *Engine) ListEvents(ctx context.Context, query iam.EventQuery) (iam.EventPage, error) {
	out := iam.EventPage{Events: []iam.Event{}, RetentionSeconds: int64(s.cfg.EventRetention / time.Second)}
	if err := s.requirePG(); err != nil {
		return out, err
	}
	scope := "authority"
	if !query.Authority {
		tenant, err := s.tenantID(ctx)
		if err != nil {
			return out, err
		}
		scope = tenant.String()
	}
	types := append([]string(nil), query.Types...)
	for _, kind := range query.Kinds {
		types = append(types, string(kind))
	}
	log := eventlog.Log{Source: "authkit", Scope: scope, Retention: s.cfg.EventRetention,
		Now: s.nowTime, Codec: authEventCursor{}, SkipFloorBoundary: true,
		ReadSnapshot: func(ctx context.Context, read func(eventlog.Snapshot) error) error {
			tx, err := s.pg.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
			if err != nil {
				return err
			}
			defer tx.Rollback(ctx)
			if err := read(&authEventSnapshot{q: s.qtx(tx), scope: scope}); err != nil {
				return err
			}
			return tx.Commit(ctx)
		},
	}
	// Existing Kinds cursors bind exact strings, including outer whitespace.
	// New Types requests use the shared normalization policy.
	if len(query.Types) == 0 {
		log.NormalizeQuery = legacyEventQuery
	}
	page, err := log.ListEvents(ctx, eventlog.Query{After: query.After, Types: types, Limit: query.Limit})
	if errors.Is(err, eventlog.ErrExpiredCursor) {
		return out, iam.ErrEventCursorExpired
	}
	if errors.Is(err, eventlog.ErrInvalidCursor) {
		return out, errmodel.E(errmodel.CodeInvalidRequest, errmodel.WithParam("after"))
	}
	if errors.Is(err, eventlog.ErrInvalidQuery) {
		param := "type"
		if query.Limit < 0 || query.Limit > eventlog.MaxLimit {
			param = "limit"
		}
		return out, errmodel.E(errmodel.CodeInvalidRequest, errmodel.WithParam(param))
	}
	if err != nil {
		return out, err
	}
	out.NextCursor, out.HasMore, out.RetentionSeconds = page.NextCursor, page.HasMore, page.RetentionSeconds
	for _, record := range page.Events {
		var event iam.Event
		if err := json.Unmarshal(record.Data, &event); err != nil {
			return out, err
		}
		event.RecordedAt = record.RecordedAt
		out.Events = append(out.Events, event)
	}
	return out, nil
}

func legacyEventQuery(q eventlog.Query) (eventlog.Query, error) {
	normalized, err := eventlog.Normalize(q)
	if err != nil {
		return normalized, err
	}
	normalized.Types = slices.Clone(q.Types)
	slices.Sort(normalized.Types)
	normalized.Types = slices.Compact(normalized.Types)
	return normalized, nil
}

type authEventCursor struct{}

func (authEventCursor) Encode(c eventlog.Cursor) string {
	return cursor.Encode(eventLogCursor{Version: 1, Epoch: c.Epoch, Scope: c.Scope, Kinds: c.Types, Position: c.Position, EventID: c.Boundary})
}
func (authEventCursor) Decode(raw string) (eventlog.Cursor, error) {
	var c eventLogCursor
	if len(raw) > 32768 || cursor.Decode(raw, &c) != nil || c.Version != 1 || c.Position < 0 {
		return eventlog.Cursor{}, eventlog.ErrInvalidCursor
	}
	return eventlog.Cursor{Version: c.Version, Source: "authkit", Scope: c.Scope, Epoch: c.Epoch, Types: c.Kinds, Position: c.Position, Boundary: c.EventID}, nil
}

type authEventSnapshot struct {
	q      *db.Queries
	scope  string
	cutoff time.Time
}

func (s *authEventSnapshot) Stream(ctx context.Context, cutoff time.Time) (eventlog.Stream, error) {
	s.cutoff = cutoff
	state, err := s.q.EventLogSnapshot(ctx, db.EventLogSnapshotParams{Scope: &s.scope, Cutoff: &cutoff})
	if err != nil {
		return eventlog.Stream{}, err
	}
	stream := eventlog.Stream{Epoch: state.Epoch, Head: eventlog.Position{Number: state.Head}, Floor: eventlog.Position{Number: state.RetainedAfter}}
	if state.Head > state.RetainedAfter {
		stream.Head.ID, err = s.Boundary(ctx, state.Head)
	}
	return stream, err
}
func (s *authEventSnapshot) Boundary(ctx context.Context, position int64) (string, error) {
	id, err := s.q.EventLogPosition(ctx, db.EventLogPositionParams{Scope: s.scope, Position: position})
	if errors.Is(err, pgx.ErrNoRows) {
		err = eventlog.ErrExpiredCursor
	}
	return id, err
}
func (s *authEventSnapshot) Events(ctx context.Context, after int64, types []string, limit int) ([]eventlog.Record, error) {
	if types == nil {
		types = []string{}
	}
	rows, err := s.q.EventLogItems(ctx, db.EventLogItemsParams{Scope: s.scope, AfterPosition: after, Cutoff: s.cutoff, Kinds: types, PageLimit: int64(limit)})
	if err != nil {
		return nil, err
	}
	records := make([]eventlog.Record, 0, len(rows))
	for _, row := range rows {
		var payload iam.Event
		if err := json.Unmarshal(row.Payload, &payload); err != nil {
			return nil, fmt.Errorf("authkit: decode retained event %s: %w", row.EventID, err)
		}
		if string(payload.Kind) != row.Kind {
			return nil, fmt.Errorf("authkit: retained event %s kind differs from payload", row.EventID)
		}
		records = append(records, eventlog.Record{Position: row.Position, Event: eventlog.Event{ID: row.EventID, Source: "authkit", Scope: s.scope, Type: row.Kind, Version: payload.Version, OccurredAt: payload.OccurredAt, RecordedAt: row.RecordedAt.UTC(), Data: row.Payload}})
	}
	return records, nil
}

// pruneEventLog uses the existing auth maintenance tick, at most 100 scopes
// and 5,000 rows per scope. It never examines or stores reader progress.
func (s *Engine) pruneEventLog(ctx context.Context) error {
	scopes, err := s.q.EventLogDueScopes(ctx, s.nowTime().Add(-s.cfg.EventRetention))
	if err != nil {
		return err
	}
	for _, scope := range scopes {
		store, err := eventpg.New(s.pg, eventpg.Config{Schema: s.dbSchema(), Source: "authkit", Scope: scope, Retention: s.cfg.EventRetention, Now: s.nowTime})
		if err != nil {
			return err
		}
		if _, err = store.Prune(ctx, 5000); err != nil {
			return err
		}
	}
	return nil
}
