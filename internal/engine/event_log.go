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

// appendEventLog locks all affected scopes in stable order before assigning
// positions. Each lock survives until the caller's mutation commits or rolls
// back: a reader can never advance past an allocated but uncommitted position.
func (s *Engine) appendEventLog(ctx context.Context, tx pgx.Tx, events []iam.Event) error {
	q := s.qtx(tx)
	scopes := make([]string, 0, len(events))
	for _, e := range events {
		scopes = append(scopes, eventLogScope(e.TenantID))
	}
	slices.Sort(scopes)
	scopes = slices.Compact(scopes)
	positions := make(map[string]int64, len(scopes))
	for _, scope := range scopes {
		if err := q.EventLogCreateScope(ctx, scope); err != nil {
			return err
		}
		state, err := q.EventLogLockScope(ctx, scope)
		if err != nil {
			return err
		}
		positions[scope] = state.Position
	}
	for _, e := range events {
		scope := eventLogScope(e.TenantID)
		positions[scope]++
		payload, err := json.Marshal(e)
		if err != nil {
			return err
		}
		if err := q.EventLogInsert(ctx, db.EventLogInsertParams{Scope: scope, Position: positions[scope],
			EventID: e.ID, Kind: string(e.Kind), Payload: payload}); err != nil {
			return err
		}
	}
	for _, scope := range scopes {
		if err := q.EventLogAdvanceScope(ctx, db.EventLogAdvanceScopeParams{Scope: scope, Position: positions[scope]}); err != nil {
			return err
		}
	}
	return nil
}

// ListEvents reads one authorized scope using shared paging and the historical
// AuthKit cursor codec. Storage and producer transactions remain unchanged.
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
		records = append(records, eventlog.Record{Position: row.Position, Event: eventlog.Event{ID: row.EventID, Source: "authkit", Scope: s.scope, Type: string(payload.Kind), Version: payload.Version, OccurredAt: payload.OccurredAt, RecordedAt: row.RecordedAt.UTC(), Data: row.Payload}})
	}
	return records, nil
}

// pruneEventLog uses the existing auth maintenance tick, at most 100 scopes
// and 5,000 rows per scope. It never examines or stores reader progress.
func (s *Engine) pruneEventLog(ctx context.Context) error {
	cutoff := s.nowTime().Add(-s.cfg.EventRetention)
	scopes, err := s.q.EventLogDueScopes(ctx, cutoff)
	if err != nil {
		return err
	}
	for _, scope := range scopes {
		err := func() error {
			tx, err := s.pg.Begin(ctx)
			if err != nil {
				return err
			}
			defer tx.Rollback(ctx)
			q := s.qtx(tx)
			if _, err := q.EventLogLockScope(ctx, scope); err != nil {
				return err
			}
			if _, err := q.EventLogPrune(ctx, db.EventLogPruneParams{Scope: &scope, Cutoff: &cutoff}); err != nil {
				return err
			}
			return tx.Commit(ctx)
		}()
		if err != nil {
			return err
		}
	}
	return nil
}
