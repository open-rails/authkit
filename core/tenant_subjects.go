package core

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgconn"

	"github.com/open-rails/authkit/internal/db"
)

var ErrInvalidTenantSubject = errors.New("invalid_tenant_subject")

// TenantSubject is the minimal local record for an external OIDC subject that
// was accepted under a tenant issuer. These are NOT local users: AuthKit
// deliberately stores only the stable OIDC identity tuple
// (tenant_id, issuer, subject) plus first/last-seen timestamps.
type TenantSubject struct {
	ID         string
	TenantID   string
	Issuer     string
	Subject    string
	CreatedAt  time.Time
	LastSeenAt time.Time
}

// TouchTenantSubject records that a tenant accepted issuer+subject. The row is
// idempotent and updates last_seen_at on repeat use.
//
// tenantID is the immutable tenant uuid from the `tenant_id` claim — the only
// accepted key (hard cut: slug-keyed identity is not supported).
func (s *Service) TouchTenantSubject(ctx context.Context, tenantID, issuer, subject string) (*TenantSubject, error) {
	if err := s.requirePG(); err != nil {
		return nil, err
	}
	tenantID = strings.TrimSpace(tenantID)
	issuer = strings.TrimSpace(issuer)
	subject = strings.TrimSpace(subject)
	if tenantID == "" || issuer == "" || subject == "" {
		return nil, ErrInvalidTenantSubject
	}

	row, err := s.q.TenantSubjectTouch(ctx, db.TenantSubjectTouchParams{TenantID: tenantID, Issuer: issuer, Subject: subject})
	if err != nil {
		// A uuid that points at no tenant (FK 23503) or is malformed (22P02)
		// is an invalid credential, not an internal failure.
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && (pgErr.Code == "23503" || pgErr.Code == "22P02") {
			return nil, ErrInvalidTenantSubject
		}
		return nil, err
	}
	return &TenantSubject{ID: row.ID, TenantID: row.TenantID, Issuer: row.Issuer, Subject: row.Subject, CreatedAt: row.CreatedAt, LastSeenAt: row.LastSeenAt}, nil
}
