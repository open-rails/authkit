package postgres

import (
	"context"

	"github.com/open-rails/authkit/notify"
)

// Get reads a named receipt, including an archived one, for its recipient.
func (s *Store) Get(ctx context.Context, r notify.Recipient, id string) (notify.Item, error) {
	return s.GetRecipients(ctx, []notify.Recipient{r}, id)
}

// GetRecipients reads a receipt only when its recipient is in the host's fresh
// authorized set. An absent or newly unlinked recipient reads as not found.
func (s *Store) GetRecipients(ctx context.Context, rs []notify.Recipient, id string) (notify.Item, error) {
	audiences, ids, _, err := recipientSet(rs)
	if err != nil {
		return notify.Item{}, err
	}
	if len(ids) == 0 {
		return notify.Item{}, notify.ErrNotFound
	}
	return scan(s.pool.QueryRow(ctx, `SELECT `+columns+` FROM `+s.table+` WHERE scope=$1 AND (audience,recipient) IN (SELECT * FROM unnest($2::text[],$3::text[])) AND id=$4 `+s.readFilter(5), append([]any{s.scope, audiences, ids, id}, s.readArgs()...)...))
}

// SetReadRecipients updates authorized receipt state and returns the canonical
// item/revision. Reading does not dismiss the receipt or resolve a workflow.
func (s *Store) SetReadRecipients(ctx context.Context, rs []notify.Recipient, id string, read bool) (notify.Item, error) {
	audiences, ids, _, err := recipientSet(rs)
	if err != nil {
		return notify.Item{}, err
	}
	if len(ids) == 0 {
		return notify.Item{}, notify.ErrNotFound
	}
	return scan(s.pool.QueryRow(ctx, `UPDATE `+s.table+` SET read_at=CASE WHEN $5 THEN coalesce(read_at,clock_timestamp()) ELSE NULL END,updated_at=CASE WHEN (read_at IS NOT NULL)=$5 THEN updated_at ELSE clock_timestamp() END,revision=revision+CASE WHEN (read_at IS NOT NULL)=$5 THEN 0 ELSE 1 END WHERE scope=$1 AND (audience,recipient) IN (SELECT * FROM unnest($2::text[],$3::text[])) AND id=$4 `+s.readFilter(6)+` RETURNING `+columns, append([]any{s.scope, audiences, ids, id, read}, s.readArgs()...)...))
}

// SetDismissed archives or restores a recipient's receipt, independently of
// read state and domain/workflow resolution.
func (s *Store) SetDismissed(ctx context.Context, r notify.Recipient, id string, dismissed bool) (notify.Item, error) {
	return s.SetDismissedRecipients(ctx, []notify.Recipient{r}, id, dismissed)
}

// SetDismissedRecipients changes only a receipt in the host's currently
// authorized set. Retried dismissal preserves its original timestamp.
func (s *Store) SetDismissedRecipients(ctx context.Context, rs []notify.Recipient, id string, dismissed bool) (notify.Item, error) {
	audiences, ids, _, err := recipientSet(rs)
	if err != nil {
		return notify.Item{}, err
	}
	if len(ids) == 0 {
		return notify.Item{}, notify.ErrNotFound
	}
	return scan(s.pool.QueryRow(ctx, `UPDATE `+s.table+` SET dismissed_at=CASE WHEN $5 THEN coalesce(dismissed_at,clock_timestamp()) ELSE NULL END,updated_at=CASE WHEN (dismissed_at IS NOT NULL)=$5 THEN updated_at ELSE clock_timestamp() END,revision=revision+CASE WHEN (dismissed_at IS NOT NULL)=$5 THEN 0 ELSE 1 END WHERE scope=$1 AND (audience,recipient) IN (SELECT * FROM unnest($2::text[],$3::text[])) AND id=$4 `+s.readFilter(6)+` RETURNING `+columns, append([]any{s.scope, audiences, ids, id, dismissed}, s.readArgs()...)...))
}
