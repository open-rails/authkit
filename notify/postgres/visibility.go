package postgres

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/open-rails/authkit/notify"
)

func appView(in *notify.AppView) (*notify.AppView, []string, []string, string, error) {
	if in == nil {
		return nil, nil, nil, "", nil
	}
	if strings.TrimSpace(in.AppID) == "" || len(in.AppID) > 512 || strings.ContainsRune(in.AppID, 0) {
		return nil, nil, nil, "", fmt.Errorf("%w: app view requires app ID", notify.ErrInvalid)
	}
	origins, systems, scopes, _, err := originSet(in.LegacyOrigins)
	if err != nil {
		return nil, nil, nil, "", err
	}
	out := &notify.AppView{AppID: in.AppID, LegacyOrigins: origins}
	b, _ := json.Marshal(out)
	digest := sha256.Sum256(b)
	return out, systems, scopes, fmt.Sprintf("%x", digest), nil
}

// readFilter is shared by lists, details, receipt mutations and workflow
// transitions, so no alternate operation weakens the application boundary.
func (s *Store) readFilter(start int) string {
	return fmt.Sprintf(`AND NOT withdrawn AND ($%d OR (source,source_scope) IN (SELECT * FROM unnest($%d::text[],$%d::text[])))
 AND ($%d OR visibility='tenant' OR (visibility='app' AND app_id=$%d)
 OR (visibility='' AND (source,source_scope) IN (SELECT * FROM unnest($%d::text[],$%d::text[]))))`, start, start+1, start+2, start+3, start+4, start+5, start+6)
}
func (s *Store) readArgs() []any {
	appID := ""
	if s.appView != nil {
		appID = s.appView.AppID
	}
	return []any{s.origins == nil, s.originSystems, s.originScopes, s.appView == nil, appID, s.legacySystems, s.legacyScopes}
}

// LegacyVisibility is an explicit migration claim about one producer scope.
// It does not alter the producer identity or relabel already classified rows.
type LegacyVisibility struct {
	Origin     notify.OriginScope
	Visibility notify.Visibility
	AppID      string
}

// ClassifyLegacyOrigins labels only currently unclassified receipts. Run with
// writers stopped after verifying each producer scope's ownership. A conflicting
// explicit classification aborts the whole operation; read/archive state and IDs
// survive. Versioned unclassified rows require exact source-state adoption;
// relabeling them would invalidate producer replay. Normal Publish replay never
// performs this migration implicitly.
func (s *Store) ClassifyLegacyOrigins(ctx context.Context, mappings []LegacyVisibility) (int64, error) {
	unique := map[notify.OriginScope]LegacyVisibility{}
	for _, m := range mappings {
		if m.Visibility == "" {
			return 0, fmt.Errorf("%w: classification required", notify.ErrInvalid)
		}
		_, err := notify.Validate(notify.Input{Recipient: notify.Recipient{Audience: notify.AudienceUser, ID: "migration"}, Origin: notify.Origin{System: m.Origin.System, Scope: m.Origin.Scope, ID: "classification"}, Kind: "migration", CreatedAt: time.Now(), Visibility: m.Visibility, AppID: m.AppID})
		if err != nil {
			return 0, err
		}
		if old, ok := unique[m.Origin]; ok && old != m {
			return 0, fmt.Errorf("%w: ambiguous legacy origin", notify.ErrConflict)
		}
		unique[m.Origin] = m
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, `LOCK TABLE `+s.table+` IN SHARE ROW EXCLUSIVE MODE`); err != nil {
		return 0, err
	}
	var count int64
	for _, m := range unique {
		var conflict bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM `+s.table+` WHERE scope=$1 AND source=$2 AND source_scope=$3 AND visibility='' AND producer_revision>0)`, s.scope, m.Origin.System, m.Origin.Scope).Scan(&conflict); err != nil {
			return 0, err
		}
		if conflict {
			// Classification changes the producer mutation's meaning. Only its
			// authoritative source can supply a new revision and matching state.
			return 0, fmt.Errorf("%w: versioned unclassified origin requires exact source-state adoption", notify.ErrConflict)
		}
		if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM `+s.table+` WHERE scope=$1 AND source=$2 AND source_scope=$3 AND visibility<>'' AND (visibility,app_id) IS DISTINCT FROM ($4::text,$5::text))`, s.scope, m.Origin.System, m.Origin.Scope, m.Visibility, m.AppID).Scan(&conflict); err != nil {
			return 0, err
		}
		if conflict {
			return 0, fmt.Errorf("%w: classified origin differs", notify.ErrConflict)
		}
		result, err := tx.Exec(ctx, `UPDATE `+s.table+` SET visibility=$4,app_id=$5,revision=revision+1,updated_at=clock_timestamp() WHERE scope=$1 AND source=$2 AND source_scope=$3 AND visibility=''`, s.scope, m.Origin.System, m.Origin.Scope, m.Visibility, m.AppID)
		if err != nil {
			return 0, err
		}
		count += result.RowsAffected()
	}
	return count, tx.Commit(ctx)
}

func (s *Store) visible(item notify.Item) bool {
	if s.appView == nil {
		return true
	}
	switch item.Visibility {
	case notify.VisibilityTenant:
		return true
	case notify.VisibilityApp:
		return item.AppID == s.appView.AppID
	case "":
		for _, origin := range s.appView.LegacyOrigins {
			if origin.System == item.Origin.System && origin.Scope == item.Origin.Scope {
				return true
			}
		}
	}
	return false
}
