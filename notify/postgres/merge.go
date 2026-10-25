package postgres

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/open-rails/authkit/notify"
)

// LegacyScope identifies an existing, migrated inbox in the same database.
type LegacyScope struct {
	Schema string
	Scope  string
}

// MergeFrom consolidates legacy inboxes into this store without changing the
// sources. Run this maintenance operation with source and destination writers
// stopped, then switch all writers to the destination. It is not a boot hook.
//
// Duplicate origins retain one receipt, read/archive timestamps from either
// copy, and the most recently updated workflow state. Erasure wins over every
// copy. The destination's existing ID survives; otherwise the first source ID
// survives. A conflicting ID for a different origin aborts the transaction.
// Reads and receipt changes use this store's origin filter after the merge;
// the merge itself copies every origin in the explicitly named scopes.
func (s *Store) MergeFrom(ctx context.Context, sources []LegacyScope) error {
	type source struct{ schema, scope string }
	unique := map[source]bool{}
	destination := strings.TrimSuffix(s.table, ".notify_items")
	for _, in := range sources {
		name, err := schemaName(in.Schema)
		if err != nil || strings.TrimSpace(in.Scope) == "" || len(in.Scope) > 512 || strings.ContainsRune(in.Scope, 0) {
			return fmt.Errorf("%w: legacy inbox schema and scope required", notify.ErrInvalid)
		}
		if name != destination || in.Scope != s.scope {
			unique[source{name, in.Scope}] = true
		}
	}
	if len(unique) == 0 {
		return nil
	}
	ordered := make([]source, 0, len(unique))
	schemas := map[string]bool{destination: true}
	for in := range unique {
		ordered = append(ordered, in)
		schemas[in.schema] = true
	}
	sort.Slice(ordered, func(i, j int) bool {
		if ordered[i].schema == ordered[j].schema {
			return ordered[i].scope < ordered[j].scope
		}
		return ordered[i].schema < ordered[j].schema
	})
	orderedSchemas := make([]string, 0, len(schemas))
	for schema := range schemas {
		orderedSchemas = append(orderedSchemas, schema)
	}
	sort.Strings(orderedSchemas)

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	// All mergers use the same schema order, with recipient guards first as
	// in PublishTx/EraseRecipientTx. Reads may continue while writes wait.
	for _, schema := range orderedSchemas {
		if _, err := tx.Exec(ctx, `LOCK TABLE `+schema+`.notify_recipients, `+schema+`.notify_items IN SHARE ROW EXCLUSIVE MODE`); err != nil {
			return fmt.Errorf("notify: lock legacy inbox: %w", err)
		}
	}
	// Merge every guard before any item. A tombstone in a later source must
	// also fence the earlier sources and existing destination receipts.
	for _, in := range ordered {
		_, err := tx.Exec(ctx, `INSERT INTO `+s.recipients+` AS target(scope,audience,recipient,erased_at)
SELECT $1,audience,recipient,erased_at FROM `+in.schema+`.notify_recipients WHERE scope=$2
ON CONFLICT(scope,audience,recipient) DO UPDATE SET erased_at=least(target.erased_at,EXCLUDED.erased_at)
WHERE EXCLUDED.erased_at IS NOT NULL AND (target.erased_at IS NULL OR EXCLUDED.erased_at<target.erased_at)`, s.scope, in.scope)
		if err != nil {
			return fmt.Errorf("notify: merge recipient guards: %w", err)
		}
		_, err = tx.Exec(ctx, `INSERT INTO `+s.recipients+`(scope,audience,recipient)
SELECT DISTINCT $1,audience,recipient FROM `+in.schema+`.notify_items WHERE scope=$2
ON CONFLICT(scope,audience,recipient) DO NOTHING`, s.scope, in.scope)
		if err != nil {
			return fmt.Errorf("notify: merge legacy recipients: %w", err)
		}
		var hasAppFences bool
		if err := tx.QueryRow(ctx, `SELECT to_regclass($1) IS NOT NULL`, in.schema+".notify_app_erasures").Scan(&hasAppFences); err != nil {
			return err
		}
		if hasAppFences {
			if _, err := tx.Exec(ctx, `INSERT INTO `+s.appErasures+`(scope,audience,recipient,app_id,source,source_scope,erased_at)
SELECT $1,audience,recipient,app_id,source,source_scope,erased_at FROM `+in.schema+`.notify_app_erasures WHERE scope=$2 ON CONFLICT DO NOTHING`, s.scope, in.scope); err != nil {
				return err
			}
		}
	}
	if _, err := tx.Exec(ctx, `UPDATE `+s.recipients+` r SET revision=revision+1 WHERE r.scope=$1 AND EXISTS(SELECT 1 FROM `+s.appErasures+` f WHERE f.scope=r.scope AND f.audience=r.audience AND f.recipient=r.recipient)`, s.scope); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `DELETE FROM `+s.table+` i USING `+s.appErasures+` f WHERE i.scope=$1 AND f.scope=i.scope AND f.audience=i.audience AND f.recipient=i.recipient AND
((i.visibility='app' AND f.app_id<>'' AND i.app_id=f.app_id) OR (i.visibility='' AND f.source<>'' AND i.source=f.source AND i.source_scope=f.source_scope))`, s.scope); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `DELETE FROM `+s.table+` AS item USING `+s.recipients+` AS recipient
WHERE item.scope=$1 AND recipient.scope=item.scope AND recipient.audience=item.audience
AND recipient.recipient=item.recipient AND recipient.erased_at IS NOT NULL`, s.scope); err != nil {
		return fmt.Errorf("notify: apply merged erasure fences: %w", err)
	}
	for _, in := range ordered {
		var fields int
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM pg_attribute WHERE attrelid=to_regclass($1) AND attname IN ('visibility','app_id') AND NOT attisdropped`, in.schema+".notify_items").Scan(&fields); err != nil {
			return err
		}
		selected := visibilityColumns
		visibility, appID := "item.visibility", "item.app_id"
		switch fields {
		case 0:
			selected = legacyColumns + `,''::text AS visibility,''::text AS app_id`
			visibility, appID = "''::text", "''::text"
		case 2:
			var conflict bool
			if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM `+in.schema+`.notify_items source JOIN `+s.table+` target ON target.scope=$1 AND target.audience=source.audience AND target.recipient=source.recipient AND target.source=source.source AND target.source_scope=source.source_scope AND target.source_id=source.source_id
                WHERE source.scope=$2 AND source.visibility<>'' AND target.visibility<>'' AND (source.visibility,source.app_id) IS DISTINCT FROM (target.visibility,target.app_id))`, s.scope, in.scope).Scan(&conflict); err != nil {
				return err
			}
			if conflict {
				return fmt.Errorf("%w: legacy origin has conflicting visibility", notify.ErrConflict)
			}
		default:
			return fmt.Errorf("%w: incomplete legacy visibility schema", notify.ErrInvalid)
		}
		var producerFields int
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM pg_attribute WHERE attrelid=to_regclass($1) AND attname IN ('producer_revision','withdrawn','producer_hash') AND NOT attisdropped`, in.schema+".notify_items").Scan(&producerFields); err != nil {
			return err
		}
		switch producerFields {
		case 0:
			selected += `,0::bigint AS producer_revision,false AS withdrawn,NULL::bytea AS producer_hash`
		case 3:
			selected += `,producer_revision,withdrawn,producer_hash`
			var conflict bool
			if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM `+in.schema+`.notify_items source JOIN `+s.table+` target ON target.scope=$1 AND target.audience=source.audience AND target.recipient=source.recipient AND target.source=source.source AND target.source_scope=source.source_scope AND target.source_id=source.source_id
WHERE source.scope=$2 AND source.producer_revision>0 AND source.producer_revision=target.producer_revision AND source.producer_hash IS DISTINCT FROM target.producer_hash)`, s.scope, in.scope).Scan(&conflict); err != nil {
				return err
			}
			if conflict {
				return fmt.Errorf("%w: legacy producer revision has different content", notify.ErrConflict)
			}
		default:
			return fmt.Errorf("%w: incomplete legacy producer schema", notify.ErrInvalid)
		}
		_, err := tx.Exec(ctx, `INSERT INTO `+s.table+` AS target(scope,`+columns+`,producer_hash)
SELECT $1,`+selected+` FROM `+in.schema+`.notify_items AS item WHERE scope=$2
AND NOT EXISTS (SELECT 1 FROM `+s.recipients+` AS recipient WHERE recipient.scope=$1
 AND recipient.audience=item.audience AND recipient.recipient=item.recipient AND recipient.erased_at IS NOT NULL)
AND NOT EXISTS (SELECT 1 FROM `+s.appErasures+` f WHERE f.scope=$1 AND f.audience=item.audience AND f.recipient=item.recipient AND
((`+visibility+`='app' AND f.app_id<>'' AND `+appID+`=f.app_id) OR (`+visibility+`='' AND f.source<>'' AND item.source=f.source AND item.source_scope=f.source_scope)))
ON CONFLICT(scope,audience,recipient,source,source_scope,source_id) DO UPDATE SET
 read_at=least(target.read_at,EXCLUDED.read_at),
 dismissed_at=least(target.dismissed_at,EXCLUDED.dismissed_at),
 kind=CASE WHEN EXCLUDED.producer_revision>target.producer_revision THEN EXCLUDED.kind ELSE target.kind END,
 data=CASE WHEN EXCLUDED.producer_revision>target.producer_revision THEN EXCLUDED.data ELSE target.data END,
 created_at=CASE WHEN EXCLUDED.producer_revision>target.producer_revision THEN EXCLUDED.created_at ELSE target.created_at END,
 source_subject=CASE WHEN EXCLUDED.producer_revision>target.producer_revision THEN EXCLUDED.source_subject ELSE target.source_subject END,
 severity=CASE WHEN EXCLUDED.producer_revision>target.producer_revision THEN EXCLUDED.severity ELSE target.severity END,
 status=CASE WHEN EXCLUDED.producer_revision>target.producer_revision OR (EXCLUDED.producer_revision=target.producer_revision AND EXCLUDED.updated_at>target.updated_at) THEN EXCLUDED.status ELSE target.status END,
 resolved_at=CASE WHEN EXCLUDED.producer_revision>target.producer_revision OR (EXCLUDED.producer_revision=target.producer_revision AND EXCLUDED.updated_at>target.updated_at) THEN EXCLUDED.resolved_at ELSE target.resolved_at END,
 action_requested=CASE WHEN EXCLUDED.producer_revision>target.producer_revision THEN EXCLUDED.action_requested ELSE target.action_requested OR EXCLUDED.action_requested END,
 producer_revision=greatest(target.producer_revision,EXCLUDED.producer_revision),
 producer_hash=CASE WHEN EXCLUDED.producer_revision>target.producer_revision THEN EXCLUDED.producer_hash ELSE target.producer_hash END,
 withdrawn=CASE WHEN EXCLUDED.producer_revision>target.producer_revision THEN EXCLUDED.withdrawn ELSE target.withdrawn END,
 updated_at=greatest(target.updated_at,EXCLUDED.updated_at),
 revision=greatest(target.revision,EXCLUDED.revision)+1
WHERE (target.read_at,target.dismissed_at,target.status,target.resolved_at,target.action_requested)
 IS DISTINCT FROM (least(target.read_at,EXCLUDED.read_at),least(target.dismissed_at,EXCLUDED.dismissed_at),
 CASE WHEN EXCLUDED.updated_at>target.updated_at THEN EXCLUDED.status ELSE target.status END,
 CASE WHEN EXCLUDED.updated_at>target.updated_at THEN EXCLUDED.resolved_at ELSE target.resolved_at END,
 target.action_requested OR EXCLUDED.action_requested)
 OR EXCLUDED.revision>target.revision OR EXCLUDED.producer_revision>target.producer_revision`, s.scope, in.scope)
		if err != nil {
			return fmt.Errorf("notify: merge legacy receipts: %w", err)
		}
	}
	return tx.Commit(ctx)
}
