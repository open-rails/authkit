package engine

import (
	"context"
	"time"

	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/cursor"
	"github.com/open-rails/authkit/internal/db"
)

// Ban history: users keeps the ban in force; user_ban_events keeps every ban
// and unban, written in the change's transaction (Ban, Unban, and the ban an
// imported or seeded account arrives with).

// ListBanEvents pages an account's ban history, newest first.
func (s *Engine) ListBanEvents(ctx context.Context, userID string, p iam.PageRequest) (iam.ListPage[iam.BanEvent], error) {
	out := iam.ListPage[iam.BanEvent]{Items: []iam.BanEvent{}}
	userID, ok := canonicalUUID(userID)
	if !ok {
		return out, iam.ErrUserNotFound
	}
	if err := s.requirePG(); err != nil {
		return out, err
	}
	after, err := cursor.Keys(p.Cursor, 2)
	if err != nil {
		return out, err
	}
	arg := db.BanEventsByUserParams{UserID: userID, PageLimit: int64(p.PageLimit()) + 1}
	if after[0] != "" {
		at, err := time.Parse(time.RFC3339Nano, after[0])
		if err != nil || !isUUID(after[1]) {
			return out, cursor.Invalid()
		}
		arg.AfterAt, arg.AfterID = &at, &after[1]
	}
	rows, err := s.q.BanEventsByUser(ctx, arg)
	if err != nil {
		return out, err
	}
	limit := p.PageLimit()
	for _, r := range rows[:min(len(rows), limit)] {
		out.Items = append(out.Items, iam.BanEvent{
			ID: r.ID, Kind: iam.BanEventKind(r.Kind), OccurredAt: r.OccurredAt, Until: r.BannedUntil, Reason: r.Reason, By: r.ActorID,
		})
	}
	if len(rows) > limit {
		last := rows[limit-1]
		out.Next = pageCursor(last.OccurredAt.UTC().Format(time.RFC3339Nano), last.ID)
	}
	return out, nil
}
