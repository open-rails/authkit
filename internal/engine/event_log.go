package engine

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/cursor"
	"github.com/open-rails/authkit/internal/db"
	"github.com/open-rails/authkit/internal/errmodel"
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

func eventKinds(kinds []iam.EventKind) ([]string, error) {
	out := make([]string, 0, len(kinds))
	if len(kinds) > 100 {
		return nil, errmodel.E(errmodel.CodeInvalidRequest, errmodel.WithParam("kind"))
	}
	for _, kind := range kinds {
		if strings.TrimSpace(string(kind)) == "" || len(kind) > 128 {
			return nil, errmodel.E(errmodel.CodeInvalidRequest, errmodel.WithParam("kind"))
		}
		out = append(out, string(kind))
	}
	slices.Sort(out)
	return slices.Compact(out), nil
}

// ListEvents is a read-only snapshot of one scope's retained committed log.
// The embedded caller is trusted, like ListUsers; HTTP checks permissions
// separately on every request. An empty result still has a usable cursor.
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
	limit := query.Limit
	if limit == 0 {
		limit = 100
	}
	if limit < 1 || limit > 500 {
		return out, errmodel.E(errmodel.CodeInvalidRequest, errmodel.WithParam("limit"))
	}
	kinds, err := eventKinds(query.Kinds)
	if err != nil {
		return out, err
	}
	position := eventLogCursor{Version: 1, Scope: scope, Kinds: kinds}
	if query.After != "" {
		if len(query.After) > 32768 || cursor.Decode(query.After, &position) != nil || position.Version != 1 ||
			position.Scope != scope || !slices.Equal(position.Kinds, kinds) || position.Position < 0 {
			return out, errmodel.E(errmodel.CodeInvalidRequest, errmodel.WithParam("after"))
		}
	}
	// The retention floor, head and payload rows must come from one snapshot;
	// concurrent pruning or appends cannot manufacture a skipped page.
	tx, err := s.pg.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return out, err
	}
	defer tx.Rollback(ctx)
	q := s.qtx(tx)
	cutoff := s.nowTime().Add(-s.cfg.EventRetention)
	state, err := q.EventLogSnapshot(ctx, db.EventLogSnapshotParams{Scope: &scope, Cutoff: &cutoff})
	if err != nil {
		return out, err
	}
	if query.After == "" {
		position.Epoch, position.Position = state.Epoch, state.RetainedAfter
	} else if position.Epoch != state.Epoch || position.Position < state.RetainedAfter || position.Position > state.Head {
		return out, iam.ErrEventCursorExpired
	} else if position.Position > state.RetainedAfter && position.Position > 0 {
		id, err := q.EventLogPosition(ctx, db.EventLogPositionParams{Scope: scope, Position: position.Position})
		if errors.Is(err, pgx.ErrNoRows) || err == nil && id != position.EventID {
			return out, iam.ErrEventCursorExpired
		}
		if err != nil {
			return out, err
		}
	}
	rows, err := q.EventLogItems(ctx, db.EventLogItemsParams{Scope: scope, AfterPosition: position.Position,
		Cutoff: cutoff, Kinds: kinds, PageLimit: int64(limit + 1)})
	if err != nil {
		return out, err
	}
	out.HasMore = len(rows) > limit
	for _, row := range rows[:min(len(rows), limit)] {
		var event iam.Event
		if err := json.Unmarshal(row.Payload, &event); err != nil {
			return out, fmt.Errorf("authkit: decode retained event %s: %w", row.EventID, err)
		}
		out.Events = append(out.Events, event)
		position.Position, position.EventID = row.Position, row.EventID
	}
	if !out.HasMore {
		position.Position, position.EventID = state.Head, ""
		if state.Head > state.RetainedAfter {
			position.EventID, err = q.EventLogPosition(ctx, db.EventLogPositionParams{Scope: scope, Position: state.Head})
			if err != nil {
				return out, err
			}
		}
	}
	out.NextCursor = cursor.Encode(position)
	return out, tx.Commit(ctx)
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
