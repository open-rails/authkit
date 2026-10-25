package engine

import (
	"context"
	"fmt"
	"slices"
	"sort"

	"github.com/jackc/pgx/v5"
	"github.com/open-rails/authkit/notify"
)

// AdoptNotifications is explicit native maintenance for stopped old writers.
// It maps exact legacy origins to canonical producer identities and preserves
// the chosen receipt ID/read/archive state. It never searches by a wildcard.
func (s *Engine) AdoptNotifications(ctx context.Context, producer string, adoptions []notify.Adoption) error {
	if len(adoptions) > notify.MaxMutations {
		return fmt.Errorf("%w: too many notification adoptions", notify.ErrInvalid)
	}
	p, err := s.NotificationProducer(ctx, producer)
	if err != nil {
		return err
	}
	scope, err := s.NotificationScope(ctx)
	if err != nil {
		return err
	}
	batch := slices.Clone(adoptions)
	for i := range batch {
		current, err := bindNotifications(p, []notify.Mutation{batch[i].Current})
		if err != nil {
			return err
		}
		batch[i].Current = current[0]
		if len(batch[i].Previous) > 10000 {
			return fmt.Errorf("%w: too many prior notification identities", notify.ErrInvalid)
		}
		for _, old := range batch[i].Previous {
			if old.System != p.Origin.System || old.Scope != p.Origin.Scope || old.ID == "" {
				return fmt.Errorf("%w: legacy notification identity outside producer", notify.ErrInvalid)
			}
		}
	}
	sort.Slice(batch, func(i, j int) bool {
		if batch[i].Current.Recipient.ID != batch[j].Current.Recipient.ID {
			return batch[i].Current.Recipient.ID < batch[j].Current.Recipient.ID
		}
		return batch[i].Current.Origin.ID < batch[j].Current.Origin.ID
	})
	store, err := s.notificationStore(ctx, false)
	if err != nil {
		return err
	}
	items := pgx.Identifier{s.cfg.Notifications.Schema, "notify_items"}.Sanitize()
	recipients := pgx.Identifier{s.cfg.Notifications.Schema, "notify_recipients"}.Sanitize()
	appFences := pgx.Identifier{s.cfg.Notifications.Schema, "notify_app_erasures"}.Sanitize()
	return pgx.BeginFunc(ctx, s.pg, func(tx pgx.Tx) error {
		if err := s.checkNotificationScope(ctx, tx); err != nil {
			return err
		}
		// Writers are stopped by the cutover owner. These short locks also keep a
		// concurrent receipt update/erasure from observing half an adoption batch.
		if _, err := tx.Exec(ctx, "LOCK TABLE "+recipients+", "+items+", "+appFences+" IN SHARE ROW EXCLUSIVE MODE"); err != nil {
			return err
		}
		for _, adoption := range batch {
			m := adoption.Current
			ids := []string{m.Origin.ID}
			for _, old := range adoption.Previous {
				ids = append(ids, old.ID)
			}
			type prior struct {
				id, sourceID string
				visibility   notify.Visibility
				app          string
				revision     int64
				withdrawn    bool
			}
			rows, err := tx.Query(ctx, `SELECT id,source_id,visibility,app_id,producer_revision,withdrawn FROM `+items+`
WHERE scope=$1 AND audience='user' AND recipient=$2 AND source=$3 AND source_scope=$4 AND source_id=ANY($5)
ORDER BY (source_id=$6) DESC,created_at DESC,id DESC FOR UPDATE`, scope, m.Recipient.ID, p.Origin.System, p.Origin.Scope, ids, m.Origin.ID)
			if err != nil {
				return err
			}
			priorRows, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (prior, error) {
				var r prior
				err := row.Scan(&r.id, &r.sourceID, &r.visibility, &r.app, &r.revision, &r.withdrawn)
				return r, err
			})
			if err != nil {
				return err
			}
			for _, r := range priorRows {
				if r.visibility == "" && r.revision > 0 {
					return fmt.Errorf("%w: versioned unclassified receipt requires explicit producer migration", notify.ErrConflict)
				}
				if r.sourceID != m.Origin.ID && r.revision > 0 && !r.withdrawn {
					return fmt.Errorf("%w: versioned legacy identity is still active", notify.ErrConflict)
				}
				if r.visibility != "" && (r.visibility != m.Visibility || r.app != m.AppID) {
					return fmt.Errorf("%w: legacy notification visibility differs", notify.ErrConflict)
				}
			}
			if len(priorRows) == 0 && !m.Withdrawn {
				continue
			}
			if len(priorRows) > 0 {
				canonical := priorRows[0]
				if canonical.sourceID != m.Origin.ID && canonical.revision != 0 {
					return fmt.Errorf("%w: versioned legacy identity cannot be renamed", notify.ErrConflict)
				}
				if canonical.sourceID != m.Origin.ID || canonical.visibility == "" {
					if _, err := tx.Exec(ctx, `UPDATE `+items+` SET source_id=$3,visibility=$4,app_id=$5 WHERE scope=$1 AND id=$2`, scope, canonical.id, m.Origin.ID, m.Visibility, m.AppID); err != nil {
						return err
					}
				}
				for _, redundant := range priorRows[1:] {
					// Retire exact legacy identities through the same durable
					// mutation contract, including its revision/hash invariant.
					if redundant.visibility == "" {
						if _, err := tx.Exec(ctx, `UPDATE `+items+` SET visibility=$3,app_id=$4 WHERE scope=$1 AND id=$2`, scope, redundant.id, m.Visibility, m.AppID); err != nil {
							return err
						}
					}
					retired := notify.Mutation{Input: notify.Input{Recipient: m.Recipient, Origin: notify.Origin{System: p.Origin.System, Scope: p.Origin.Scope, ID: redundant.sourceID}, Visibility: m.Visibility, AppID: m.AppID}, Revision: 1, Withdrawn: true}
					if err := store.ApplyTx(ctx, tx, []notify.Mutation{retired}); err != nil {
						return err
					}
				}
			}
			if err := s.ApplyNotificationsTx(ctx, tx, producer, []notify.Mutation{m}); err != nil {
				return err
			}
		}
		return nil
	})
}
