package embedded

// Cross-site erasure handoff. A deletion raises one obligation with one
// acknowledgement per configured account issuer; the purge listing offers only
// fully acknowledged accounts, so a site that is offline or behind on its
// listing receives the obligation before the identity goes. Acknowledging
// means "durably recorded in my ledger", not "erased".

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	authkit "github.com/open-rails/authkit"
	"github.com/open-rails/authkit/internal/db"
)

const (
	defaultErasurePage = 500
	erasureCursorSep   = "/"
)

// ListUsersDeletedBefore lists accounts deleted before cutoff whose erasure
// obligation every required site acknowledged — the purge-ready set. An
// unacknowledged account is retained and never listed, and the backlog is not
// walked, so the page advances whatever the backlog size.
func (s *engine) ListUsersDeletedBefore(ctx context.Context, cutoff time.Time, limit int) ([]string, error) {
	if s.pg == nil {
		return nil, nil
	}
	if limit <= 0 {
		limit = defaultErasurePage
	}
	return s.q.ErasurePurgeCandidates(ctx, db.ErasurePurgeCandidatesParams{Cutoff: cutoff, MaxRows: int64(limit)})
}

// HardDeleteUser permanently deletes the user row and dependent AuthKit rows
// via ON DELETE CASCADE; the erasure obligation survives until acknowledged.
func (s *engine) HardDeleteUser(ctx context.Context, userID string) error {
	return s.AdminDeleteUser(ctx, userID)
}

// ListErasureObligations pages the obligations site has not acknowledged over
// the (created_at, user_id) keyset; after is "" for the first page and next is
// "" on the last one.
func (s *engine) ListErasureObligations(ctx context.Context, site, after string, limit int) ([]authkit.ErasureObligation, string, error) {
	if s.pg == nil {
		return nil, "", nil
	}
	site = strings.TrimSpace(site)
	if site == "" {
		return nil, "", errors.New("authkit: erasure site is required")
	}
	if limit <= 0 {
		limit = defaultErasurePage
	}
	afterAt, afterID, err := decodeErasureCursor(after)
	if err != nil {
		return nil, "", err
	}
	rows, err := s.q.ErasureObligationsPendingForIssuer(ctx, db.ErasureObligationsPendingForIssuerParams{
		Issuer: site, AfterCreatedAt: afterAt, AfterUserID: afterID, MaxRows: int64(limit),
	})
	if err != nil {
		return nil, "", err
	}
	page := make([]authkit.ErasureObligation, len(rows))
	for i, r := range rows {
		page[i] = authkit.ErasureObligation{
			UserID: r.UserID, Email: deref(r.Email), Username: deref(r.Username), PhoneNumber: deref(r.PhoneNumber),
			CreatedAt: r.CreatedAt, PurgedAt: r.PurgedAt,
		}
	}
	next := ""
	if len(rows) == limit {
		last := rows[len(rows)-1]
		next = last.CreatedAt.UTC().Format(time.RFC3339Nano) + erasureCursorSep + last.UserID
	}
	return page, next, nil
}

// AcknowledgeErasure marks site's acknowledgement and closes the obligation
// once the identity is purged and no acknowledgement is outstanding. The
// obligation row is locked so concurrent final acknowledgements cannot both
// miss the close.
func (s *engine) AcknowledgeErasure(ctx context.Context, site, userID string) error {
	if s.pg == nil {
		return nil
	}
	site = strings.TrimSpace(site)
	if site == "" {
		return errors.New("authkit: erasure site is required")
	}
	tx, err := s.pg.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	q := s.qtx(tx)
	// Lock first: concurrent final acknowledgements then serialize here, and
	// each recomputes readiness against a snapshot that includes the other.
	if _, err := q.ErasureObligationLock(ctx, userID); errors.Is(err, pgx.ErrNoRows) {
		return nil // unknown or already closed
	} else if err != nil {
		return err
	}
	if _, err := q.ErasureAcknowledge(ctx, db.ErasureAcknowledgeParams{UserID: userID, Issuer: site}); err != nil {
		return err
	}
	if err := q.ErasureObligationRefreshPending(ctx, userID); err != nil {
		return err
	}
	if _, err := q.ErasureObligationCloseIfSettled(ctx, userID); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// ErasureBacklog reports unacknowledged obligations per site.
func (s *engine) ErasureBacklog(ctx context.Context) ([]authkit.ErasureSiteBacklog, error) {
	if s.pg == nil {
		return nil, nil
	}
	rows, err := s.q.ErasureObligationsBacklog(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]authkit.ErasureSiteBacklog, len(rows))
	for i, r := range rows {
		out[i] = authkit.ErasureSiteBacklog{Site: r.Issuer, Pending: int(r.Pending), Oldest: r.OldestCreatedAt}
	}
	return out, nil
}

// raiseErasureObligationTx records userID's obligation (identifiers captured
// from the still-present users row) and requires every account issuer.
func (s *engine) raiseErasureObligationTx(ctx context.Context, q *db.Queries, userID string) error {
	if err := q.ErasureObligationRecord(ctx, userID); err != nil {
		return err
	}
	// Record's ON CONFLICT DO NOTHING does not lock an existing obligation.
	// Serialize with acknowledgements before their child rows are inspected:
	// an UPDATE that waits for the row lock already holds a statement snapshot
	// and could otherwise restore a stale pending_sites count after an ACK.
	if _, err := q.ErasureObligationLock(ctx, userID); err != nil {
		return err
	}
	if err := q.ErasureAcknowledgementsRequire(ctx, db.ErasureAcknowledgementsRequireParams{UserID: userID, Issuers: s.accountIssuers()}); err != nil {
		return err
	}
	return q.ErasureObligationRefreshPending(ctx, userID)
}

// settleErasureObligationTx marks the identity purged and closes the
// obligation when nothing is outstanding.
func settleErasureObligationTx(ctx context.Context, q *db.Queries, userID string) error {
	if err := q.ErasureObligationMarkPurged(ctx, userID); err != nil {
		return err
	}
	_, err := q.ErasureObligationCloseIfSettled(ctx, userID)
	return err
}

func decodeErasureCursor(cursor string) (time.Time, string, error) {
	if cursor == "" {
		return time.Time{}, "00000000-0000-0000-0000-000000000000", nil
	}
	at, id, ok := strings.Cut(cursor, erasureCursorSep)
	if !ok {
		return time.Time{}, "", fmt.Errorf("authkit: malformed erasure cursor")
	}
	t, err := time.Parse(time.RFC3339Nano, at)
	if err != nil {
		return time.Time{}, "", fmt.Errorf("authkit: malformed erasure cursor")
	}
	if _, err := uuid.Parse(id); err != nil {
		return time.Time{}, "", fmt.Errorf("authkit: malformed erasure cursor")
	}
	return t, id, nil
}

func deref(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}
