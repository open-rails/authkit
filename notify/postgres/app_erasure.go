package postgres

import (
	"context"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/open-rails/authkit/notify"
)

// EraseAppRecipient permanently erases one app's receipts, including its
// explicitly identified legacy native origin. Tenant-wide notices and other
// apps survive. This is an erasure boundary, not an inbox dismiss/reset action.
// IDs and origin come from trusted deployment configuration, never a request.
func (s *Store) EraseAppRecipient(ctx context.Context, r notify.Recipient, appID string, legacy notify.OriginScope) error {
	if appID != strings.TrimSpace(appID) || len(appID) > 512 || strings.ContainsRune(appID, 0) {
		return fmt.Errorf("%w: invalid app ID", notify.ErrInvalid)
	}
	if legacy != (notify.OriginScope{}) {
		if _, _, _, _, err := originSet([]notify.OriginScope{legacy}); err != nil {
			return err
		}
	}
	if appID == "" && legacy == (notify.OriginScope{}) {
		return fmt.Errorf("%w: app ID or exact legacy origin is required", notify.ErrInvalid)
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if _, err := s.lock(ctx, tx, r); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `UPDATE `+s.recipients+` SET revision=revision+1 WHERE scope=$1 AND audience=$2 AND recipient=$3`, s.scope, r.Audience, r.ID); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `INSERT INTO `+s.appErasures+`(scope,audience,recipient,app_id,source,source_scope) VALUES($1,$2,$3,$4,$5,$6) ON CONFLICT DO NOTHING`, s.scope, r.Audience, r.ID, appID, legacy.System, legacy.Scope); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `DELETE FROM `+s.table+` WHERE scope=$1 AND audience=$2 AND recipient=$3 AND
((visibility='app' AND $4<>'' AND app_id=$4) OR (visibility='' AND $5<>'' AND source=$5 AND source_scope=$6))`, s.scope, r.Audience, r.ID, appID, legacy.System, legacy.Scope); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (s *Store) appErased(ctx context.Context, q pgx.Tx, in notify.Input) (bool, error) {
	if in.Visibility == notify.VisibilityTenant {
		return false, nil
	}
	var erased bool
	err := q.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM `+s.appErasures+` WHERE scope=$1 AND audience=$2 AND recipient=$3 AND
(($4='app' AND app_id<>'' AND app_id=$5) OR ($4='' AND source<>'' AND source=$6 AND source_scope=$7)))`, s.scope, in.Recipient.Audience, in.Recipient.ID, in.Visibility, in.AppID, in.Origin.System, in.Origin.Scope).Scan(&erased)
	return erased, err
}

// AppErasedRecipients pages permanent account/app fences for trusted restore
// reconciliation. Only this app's explicit and native legacy fences join the
// whole-account tombstones. The caller must finish replay before serving.
func (s *Store) AppErasedRecipients(ctx context.Context, audience notify.Audience, appID string, legacy notify.OriginScope, after string, limit int) ([]notify.Recipient, error) {
	if err := notify.ValidateRecipient(notify.Recipient{Audience: audience, ID: "validation"}); err != nil {
		return nil, err
	}
	if limit < 1 || limit > 1000 {
		return nil, fmt.Errorf("%w: erasure page limit must be 1-1000", notify.ErrInvalid)
	}
	rows, err := s.pool.Query(ctx, `SELECT recipient FROM `+s.recipients+` r WHERE scope=$1 AND audience=$2 AND recipient>$3 AND
(erased_at IS NOT NULL OR EXISTS(SELECT 1 FROM `+s.appErasures+` f WHERE f.scope=r.scope AND f.audience=r.audience AND f.recipient=r.recipient AND
((f.app_id<>'' AND f.app_id=$4) OR (f.source<>'' AND f.source=$5 AND f.source_scope=$6)))) ORDER BY recipient LIMIT $7`, s.scope, audience, after, appID, legacy.System, legacy.Scope, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []notify.Recipient{}
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out = append(out, notify.Recipient{Audience: audience, ID: id})
	}
	return out, rows.Err()
}
